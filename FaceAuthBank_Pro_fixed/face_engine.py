"""
FaceAuthBank — Real Face Recognition Engine
Uses OpenCV Haar Cascade (detection) + LBPH (recognition).
No external model downloads needed — fully built into OpenCV.

Flow:
  Enroll : extract face from image → train LBPH → save model .yml
  Verify : extract face from image → predict with LBPH → compare confidence
"""

import cv2
import numpy as np
import os
import base64
import logging

CASCADE_PATH = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
FACE_DIR     = os.path.join(os.path.dirname(__file__), 'face_data')

os.makedirs(FACE_DIR, exist_ok=True)

# ─── Face detector (shared instance) ────────────────────
_detector = cv2.CascadeClassifier(CASCADE_PATH)
if _detector.empty():
    raise RuntimeError("Haar cascade not found at: " + CASCADE_PATH)

# ─── Helpers ─────────────────────────────────────────────

def _decode_image(b64_data: str) -> np.ndarray | None:
    """Decode base64 image string (data:image/...;base64,...) to BGR numpy array."""
    try:
        if ',' in b64_data:
            b64_data = b64_data.split(',', 1)[1]
        img_bytes = base64.b64decode(b64_data)
        arr = np.frombuffer(img_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img
    except Exception as e:
        logging.error(f"[FaceEngine] decode error: {e}")
        return None


def _extract_face(img: np.ndarray, size=(200, 200)) -> np.ndarray | None:
    """
    Detect largest face in image, crop it, convert to grayscale, resize.
    Returns None if no face found.
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.equalizeHist(gray)  # improve contrast

    faces = _detector.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(60, 60),
        flags=cv2.CASCADE_SCALE_IMAGE
    )

    if len(faces) == 0:
        return None

    # Pick largest face
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])

    # Add 20% padding
    pad = int(0.2 * w)
    x1 = max(0, x - pad)
    y1 = max(0, y - pad)
    x2 = min(gray.shape[1], x + w + pad)
    y2 = min(gray.shape[0], y + h + pad)

    face_crop = gray[y1:y2, x1:x2]
    face_resized = cv2.resize(face_crop, size)
    return face_resized


def _model_path(user_id: str) -> str:
    return os.path.join(FACE_DIR, f"{user_id}_lbph.yml")


# ─── Public API ──────────────────────────────────────────

def enroll_face(user_id: str, frames_b64: list[str]) -> dict:
    """
    Enroll a user from 1–5 base64 image frames.
    Trains an LBPH model and saves it to face_data/<user_id>_lbph.yml
    Returns: {"success": True/False, "faces_used": N, "error": "..."}
    """
    faces = []
    labels = []

    for b64 in frames_b64:
        img = _decode_image(b64)
        if img is None:
            continue
        face = _extract_face(img)
        if face is not None:
            faces.append(face)
            labels.append(0)  # single-user model, label always 0

    if len(faces) == 0:
        return {"success": False, "error": "No face detected in any frame. Please try again in better lighting.", "faces_used": 0}

    # Train LBPH recognizer
    recognizer = cv2.face.LBPHFaceRecognizer_create(
        radius=1, neighbors=8, grid_x=8, grid_y=8, threshold=100.0
    )
    recognizer.train(faces, np.array(labels, dtype=np.int32))
    recognizer.save(_model_path(user_id))

    logging.info(f"[FaceEngine] Enrolled {user_id} with {len(faces)} face samples")
    return {"success": True, "faces_used": len(faces)}


def verify_face(user_id: str, frame_b64: str, threshold: float = 75.0) -> dict:
    """
    Verify a face against the enrolled model.
    LBPH confidence: lower = better match. <threshold = verified.
    Default threshold 75 is good for webcam selfie quality.

    Returns: {"verified": True/False, "confidence": float, "error": "..."}
    """
    model_file = _model_path(user_id)
    if not os.path.exists(model_file):
        return {"verified": False, "confidence": 999.0, "error": "No enrolled face found. Please register first."}

    img = _decode_image(frame_b64)
    if img is None:
        return {"verified": False, "confidence": 999.0, "error": "Could not decode image."}

    face = _extract_face(img)
    if face is None:
        return {"verified": False, "confidence": 999.0, "error": "No face detected. Look directly at the camera."}

    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.read(model_file)

    label, confidence = recognizer.predict(face)
    verified = confidence < threshold

    logging.info(f"[FaceEngine] Verify {user_id}: confidence={confidence:.1f} threshold={threshold} → {'✅' if verified else '❌'}")
    return {
        "verified": verified,
        "confidence": round(float(confidence), 2),
        "threshold": threshold,
        "match_quality": f"{max(0, 100 - confidence):.0f}%"
    }


def has_enrollment(user_id: str) -> bool:
    return os.path.exists(_model_path(user_id))


def delete_enrollment(user_id: str) -> bool:
    path = _model_path(user_id)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False
