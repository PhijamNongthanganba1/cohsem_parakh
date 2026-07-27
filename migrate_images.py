import os
import shutil
UPLOAD_FOLDER = 'static/uploads/questions'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
for user_folder in os.listdir(UPLOAD_FOLDER):
    user_path = os.path.join(UPLOAD_FOLDER, user_folder)
    if os.path.isdir(user_path):
        for filename in os.listdir(user_path):
            src = os.path.join(user_path, filename)
            dst = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.move(src, dst)
                print(f"Moved: {src} -> {dst}")
        try:
            os.rmdir(user_path)
            print(f"Removed empty folder: {user_path}")
        except:
            pass
print("Migration complete!")