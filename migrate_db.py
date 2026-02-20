import os
import psycopg2

def migrate():
    # Mengambil DATABASE_URL dari environment Replit
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        print("Error: DATABASE_URL tidak ditemukan.")
        print("Pastikan Anda sudah menghubungkan Replit PostgreSQL database di tab Tools > Database.")
        return

    try:
        print(f"Menghubungkan ke database...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Menambahkan kolom base_url jika belum ada
        print("Memeriksa dan menambahkan kolom 'base_url'...")
        cursor.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS base_url TEXT NOT NULL DEFAULT '';")
        
        conn.commit()
        print("Berhasil! Kolom 'base_url' telah ditambahkan ke tabel 'api_keys'.")
        
    except Exception as e:
        print(f"Gagal melakukan migrasi: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    migrate()
