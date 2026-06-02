from database import get_db

username = "Farruxbek"  # shu yerga o'z username ingizni yozing

db = get_db()
db.execute(f"UPDATE users SET role='admin' WHERE username=?", (username,))
db.commit()
db.close()
print(f"{username} admin qilindi!")