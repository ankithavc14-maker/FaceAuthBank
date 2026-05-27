import cv2
import face_recognition
import numpy as np
import os

# Define the path to save face encodings
SAVE_PATH = "face_data"
os.makedirs(SAVE_PATH, exist_ok=True)

# Initialize webcam
video_capture = cv2.VideoCapture(0)
if not video_capture.isOpened():
    print("❌ Could not open webcam.")
    exit()

# Ask for user input to choose between user1 and user2 for enrollment
print("📸 Capturing face for enrollment.")
print("Which user are you enrolling?")
print("1. user1: Ankitha")
print("2. user2: Ramya")

user_choice = input("Enter '1' for user1 or '2' for user2: ")

# Validate user choice
if user_choice not in ['1', '2']:
    print("❌ Invalid user choice.")
    exit()

user_name = "user1" if user_choice == '1' else "user2"
print(f"📸 Please look at the camera for {user_name}... (Press 's' to save, 'q' to quit)")

while True:
    ret, frame = video_capture.read()
    if not ret:
        print("❌ Failed to grab frame.")
        break

    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    face_locations = face_recognition.face_locations(rgb_frame)

    # Draw rectangles around detected faces
    for top, right, bottom, left in face_locations:
        cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)

    # Display the frame
    cv2.imshow("Enroll Face", frame)
    key = cv2.waitKey(1) & 0xFF

    if key == ord('s'):
        if face_locations:
            # Get the encoding of the first face
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
            if face_encodings:
                # Save the encoding to a file based on the selected user
                np.save(os.path.join(SAVE_PATH, f"{user_name}.npy"), face_encodings[0])
                print(f"✅ {user_name}'s face encoding saved.")
                break
            else:
                print("❌ Face landmarks could not be extracted.")
        else:
            print("❌ No face detected. Please ensure your face is clearly visible.")
    elif key == ord('q'):
        print("👋 Enrollment cancelled.")
        break

# Release the webcam and close the window
video_capture.release()
cv2.destroyAllWindows()
