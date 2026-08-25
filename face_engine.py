"""
FaceAuthBank biometric engine.

Prototype-grade face authentication using face_recognition/dlib.
Includes:
- multi-frame enrollment and verification
- original-frame face detection with enhanced fallback
- duplicate-face detection
- basic liveness check
- brute-force lockout
- 128-D embeddings stored locally (see README for production caveats)
"""
import os, base64, json, logging
from datetime import datetime, timedelta
import cv2
import numpy as np
import face_recognition

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FACE_DIR = os.path.join(BASE_DIR, "face_data")
LOCKOUT_DIR = os.path.join(FACE_DIR, "lockouts")
os.makedirs(FACE_DIR, exist_ok=True)
os.makedirs(LOCKOUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "bank_log.txt"),
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

THRESHOLD = 0.55
DUPLICATE_THRESHOLD = 0.45
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
LIVENESS_MIN_VAR = 1e-5
LIVENESS_FRAMES = 3


def _encoding_path(user_id):
    return os.path.join(FACE_DIR, f"{user_id}.npy")

def _photo_path(user_id):
    return os.path.join(FACE_DIR, f"{user_id}.jpg")

def save_profile_photo(user_id, frames_b64):
    for item in frames_b64 or []:
        try:
            raw = item.split(',', 1)[1] if ',' in item else item
            data = base64.b64decode(raw)
            arr = np.frombuffer(data, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is None:
                continue
            cv2.imwrite(_photo_path(user_id), img, [int(cv2.IMWRITE_JPEG_QUALITY), 88])
            return True
        except Exception:
            continue
    return False

def profile_photo_path(user_id):
    path = _photo_path(user_id)
    return path if os.path.exists(path) else None


def _lockout_path(user_id):
    return os.path.join(LOCKOUT_DIR, f"{user_id}.json")


def _read_lockout(user_id):
    try:
        with open(_lockout_path(user_id), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"attempts": 0, "locked_until": None}


def _write_lockout(user_id, data):
    with open(_lockout_path(user_id), "w", encoding="utf-8") as f:
        json.dump(data, f)


def is_locked_out(user_id):
    data = _read_lockout(user_id)
    until = data.get("locked_until")
    if until:
        try:
            remaining = (datetime.fromisoformat(until) - datetime.now()).total_seconds()
            if remaining > 0:
                return True, int(remaining)
        except Exception:
            pass
        _write_lockout(user_id, {"attempts": 0, "locked_until": None})
    return False, 0


def record_failed_attempt(user_id):
    data = _read_lockout(user_id)
    attempts = int(data.get("attempts", 0)) + 1
    if attempts >= MAX_ATTEMPTS:
        until = (datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)).isoformat()
        data = {"attempts": attempts, "locked_until": until}
        _write_lockout(user_id, data)
        logging.warning(f"[FaceEngine] LOCKOUT {user_id}: {attempts} failures")
        return {"locked": True, "attempts": attempts, "seconds_remaining": LOCKOUT_SECONDS}
    data = {"attempts": attempts, "locked_until": None}
    _write_lockout(user_id, data)
    return {"locked": False, "attempts": attempts, "seconds_remaining": 0}


def reset_failed_attempts(user_id):
    _write_lockout(user_id, {"attempts": 0, "locked_until": None})


def _decode_b64_image(value):
    try:
        if not value:
            return None
        if "," in value:
            value = value.split(",", 1)[1]
        raw = base64.b64decode(value)
        frame = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        return frame
    except Exception as exc:
        logging.warning(f"[FaceEngine] image decode failed: {exc}")
        return None


def preprocess_frame(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    return cv2.cvtColor(enhanced, cv2.COLOR_GRAY2RGB)


def detect_face(frame):
    """Try the original RGB frame first; use enhanced/upsampled fallbacks."""
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    attempts = [
        (rgb, 1),
        (preprocess_frame(frame), 1),
        (rgb, 2),
    ]
    for image, upsample in attempts:
        try:
            locs = face_recognition.face_locations(
                image, model="hog", number_of_times_to_upsample=upsample
            )
            if locs:
                return image, locs
        except Exception as exc:
            logging.warning(f"[FaceEngine] face detection failed: {exc}")
    return None, []


def _get_encoding_from_frame(frame):
    rgb, locations = detect_face(frame)
    if not locations:
        return None
    largest = max(locations, key=lambda r: (r[2]-r[0]) * (r[1]-r[3]))
    try:
        encodings = face_recognition.face_encodings(rgb, [largest], num_jitters=1)
        return encodings[0] if encodings else None
    except Exception as exc:
        logging.warning(f"[FaceEngine] encoding failed: {exc}")
        return None


def _collect_encodings(frames_b64):
    if isinstance(frames_b64, str):
        frames_b64 = [frames_b64]
    encodings = []
    for value in frames_b64 or []:
        frame = _decode_b64_image(value)
        if frame is None:
            continue
        encoding = _get_encoding_from_frame(frame)
        if encoding is not None:
            encodings.append(encoding)
    return encodings


def check_liveness(encodings):
    if len(encodings) < LIVENESS_FRAMES:
        return {
            "live": False, "variance": 0.0,
            "reason": f"Need at least {LIVENESS_FRAMES} valid face frames; only {len(encodings)} detected."
        }
    try:
        stacked = np.stack(encodings)
        variance = float(np.mean(np.var(stacked, axis=0)))
        live = variance >= LIVENESS_MIN_VAR
        return {
            "live": live,
            "variance": round(variance, 8),
            "reason": "Liveness confirmed." if live else
                      "Liveness check failed. Move your head slightly and try again."
        }
    except Exception as exc:
        logging.warning(f"[FaceEngine] liveness failed: {exc}")
        return {"live": False, "variance": 0.0, "reason": "Unable to perform liveness check."}


def candidate_from_frames(frames_b64):
    """Return a mean 128-D embedding and liveness result without saving anything."""
    encodings = _collect_encodings(frames_b64)
    if not encodings:
        return None, {"live": False, "reason": "No face detected in any frame.", "faces_used": 0}
    liveness = check_liveness(encodings)
    liveness["faces_used"] = len(encodings)
    return np.mean(encodings, axis=0).astype(np.float64), liveness


def find_duplicate_face(candidate_encoding, exclude_user_id=None, threshold=DUPLICATE_THRESHOLD):
    """Compare a candidate embedding with all stored embeddings."""
    if candidate_encoding is None:
        return None
    for filename in os.listdir(FACE_DIR):
        if not filename.endswith(".npy"):
            continue
        uid = filename[:-4]
        if exclude_user_id and uid == exclude_user_id:
            continue
        try:
            stored = np.load(os.path.join(FACE_DIR, filename))
            distance = float(face_recognition.face_distance([stored], candidate_encoding)[0])
            if distance <= threshold:
                return {"user_id": uid, "distance": round(distance, 4)}
        except Exception as exc:
            logging.warning(f"[FaceEngine] duplicate scan skipped {filename}: {exc}")
    return None


def enroll_face(user_id, frames_b64):
    if len(frames_b64 or []) < 3:
        return {"success": False, "faces_used": 0, "error": "Minimum 3 camera frames required."}

    candidate, liveness = candidate_from_frames(frames_b64)
    if candidate is None:
        return {"success": False, "faces_used": 0, "liveness": liveness,
                "error": "No face detected in any frame. Ensure good lighting and face the camera directly."}
    if not liveness["live"]:
        return {"success": False, "faces_used": liveness["faces_used"],
                "liveness": liveness, "error": liveness["reason"]}

    duplicate = find_duplicate_face(candidate, exclude_user_id=user_id)
    if duplicate:
        logging.warning(f"[FaceEngine] DUPLICATE_FACE {user_id} matches {duplicate['user_id']}")
        return {
            "success": False, "duplicate": True, "duplicate_user_id": duplicate["user_id"],
            "distance": duplicate["distance"], "faces_used": liveness["faces_used"],
            "liveness": liveness,
            "error": "This face is already registered with another account."
        }

    np.save(_encoding_path(user_id), candidate)
    save_profile_photo(user_id, frames_b64)
    reset_failed_attempts(user_id)
    logging.info(f"[FaceEngine] FACE_ENROLL_SUCCESS {user_id}: {liveness['faces_used']} frames")
    return {"success": True, "faces_used": liveness["faces_used"], "liveness": liveness}


def verify_face(user_id, frames_b64, threshold=THRESHOLD):
    locked, remaining = is_locked_out(user_id)
    if locked:
        return {"verified": False, "confidence": 999.0,
                "lockout": {"locked": True, "seconds_remaining": remaining},
                "error": f"Account temporarily locked. Try again in {remaining//60}m {remaining%60}s."}

    path = _encoding_path(user_id)
    if not os.path.exists(path):
        return {"verified": False, "confidence": 999.0,
                "error": "No enrolled face found. Please register your face first."}

    try:
        stored = np.load(path)
    except Exception:
        return {"verified": False, "confidence": 999.0, "error": "Stored face data could not be loaded."}

    candidate, liveness = candidate_from_frames(frames_b64)
    if candidate is None:
        lock = record_failed_attempt(user_id)
        return {"verified": False, "confidence": 999.0, "lockout": lock,
                "error": "No face detected. Look directly at the camera in good lighting."}
    if not liveness["live"]:
        return {"verified": False, "confidence": 999.0, "liveness": liveness,
                "lockout": {"locked": False, "attempts": 0, "seconds_remaining": 0},
                "error": liveness["reason"]}

    distance = float(face_recognition.face_distance([stored], candidate)[0])
    verified = distance <= threshold
    match_pct = max(0.0, min(100.0, (1.0 - distance/threshold) * 100))
    lockout = {"locked": False, "attempts": 0, "seconds_remaining": 0}
    if verified:
        reset_failed_attempts(user_id)
        # Keep a recent verified frame as the user's profile photo.
        save_profile_photo(user_id, frames_b64)
    else:
        lockout = record_failed_attempt(user_id)

    result = {
        "verified": verified, "confidence": round(distance, 4),
        "threshold": threshold, "match_quality": f"{match_pct:.1f}%",
        "liveness": liveness, "lockout": lockout
    }
    if not verified:
        result["error"] = (
            f"Face did not match. Distance {distance:.3f} > threshold {threshold:.2f}. "
            f"Attempts: {lockout.get('attempts', 0)}/{MAX_ATTEMPTS}."
        )
    return result


def has_enrollment(user_id):
    return os.path.exists(_encoding_path(user_id))


def delete_enrollment(user_id):
    removed = False
    for path in (_encoding_path(user_id), _photo_path(user_id)):
        if os.path.exists(path):
            os.remove(path)
            removed = True
    reset_failed_attempts(user_id)
    return removed


def get_lockout_status(user_id):
    locked, remaining = is_locked_out(user_id)
    data = _read_lockout(user_id)
    return {"locked": locked, "attempts": data.get("attempts", 0),
            "max_attempts": MAX_ATTEMPTS, "seconds_remaining": remaining,
            "lockout_duration": LOCKOUT_SECONDS}
