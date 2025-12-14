import sqlite3

DATABASE = 'inventory_system.db'

def update_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    print("Veritabanı güncelleniyor...")

    # 1. Department sütununu ekle
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN department TEXT DEFAULT ''")
        print("- 'department' sütunu eklendi.")
    except sqlite3.OperationalError as e:
        print(f"- 'department' sütunu zaten var veya hata: {e}")

    # 2. Title sütununu ekle
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN title TEXT DEFAULT ''")
        print("- 'title' sütunu eklendi.")
    except sqlite3.OperationalError as e:
        print(f"- 'title' sütunu zaten var veya hata: {e}")

    conn.commit()
    conn.close()
    print("İşlem tamamlandı. Şimdi uygulamanızı (app.py) tekrar çalıştırabilirsiniz.")

if __name__ == '__main__':
    update_database()
