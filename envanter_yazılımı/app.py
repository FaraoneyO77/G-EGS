import sqlite3
import json 
import bcrypt
import random 
import string 
from flask import Flask, render_template, request, redirect, url_for, flash, g, abort, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import pandas as pd
from io import BytesIO
import re 

# -----------------
# KATEGORİ TANIMLARI
# -----------------
CATEGORIES = {
    "Donanım": ["Monitör", "Yazıcı Kartuşu", "Klavye", "Fare", "Klavye/Fare Seti", "Televizyon"],
    "Cihaz": ["Bilgisayar", "Printer", "IP Telefon", "Kamera", "Tablet", "Telefon"]
}

ALL_ITEM_TYPES = set(item for sublist in CATEGORIES.values() for item in sublist)

SHARED_ATTRIBUTE_TYPES = {}
for item_type in ALL_ITEM_TYPES:
    attrs = ["Marka/Model"] 
    
    if item_type == "Bilgisayar":
        attrs.extend(["İşlemci Tipi", "Ram Bilgisi", "Disk Bilgisi"])
    elif item_type in ["Monitör", "Televizyon"]: 
        attrs.extend(["Ekran Boyutu (İnç)", "Çözünürlük"]) 
    elif item_type in ["Tablet", "Telefon"]: 
        attrs.extend(["Ram Bilgisi", "Disk Bilgisi"])
    elif item_type == "Printer":
        attrs.extend(["Yazıcı Tipi", "Toner/Kartuş Modeli", "Kartuş Sayısı"])
    
    SHARED_ATTRIBUTE_TYPES[item_type] = attrs

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sistemin_gizli_anahtari_cok_gizli' 

def slugify(s):
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    return s

app.jinja_env.filters['slugify'] = slugify

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'inventory_system.db'

def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- YARDIMCI FONKSİYON: EAN-13 BARKOD ÜRETİCİ ---
def generate_barcode():
    """
    EAN-13 Standadına göre barkod üretir.
    İlk 12 hane rastgele oluşturulur, 13. hane (Check Digit) hesaplanır.
    """
    # 1. İlk 12 haneyi rastgele oluştur
    digits = [int(d) for d in random.choices(string.digits, k=12)]
    
    # 1. Adım: Çift hanelerin toplamı (Index 1, 3, 5...)
    even_sum = sum(digits[i] for i in range(1, 12, 2))
    
    # 2. Adım: Çıkan sayı 3 ile çarpılır
    step2 = even_sum * 3
    
    # 3. Adım: Tek hanelerin toplamı (Index 0, 2, 4...)
    odd_sum = sum(digits[i] for i in range(0, 12, 2))
    
    # 4. Adım: 2. adım ve 3. adım sonuçları toplanır
    total_sum = step2 + odd_sum
    
    # 5. Adım ve Sonuç: En yakın 10'un katından çıkartılır
    remainder = total_sum % 10
    if remainder == 0:
        check_digit = 0
    else:
        check_digit = 10 - remainder
        
    digits.append(check_digit)
    full_barcode = "".join(map(str, digits))
    
    return full_barcode

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # 1. Kullanıcılar
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            department TEXT DEFAULT '',
            title TEXT DEFAULT ''
        );
    """)

    # 2. Envanter
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            type TEXT NOT NULL,
            model_name TEXT NOT NULL,
            serial_number TEXT, 
            device_name TEXT,
            barcode TEXT,
            quantity INTEGER NOT NULL,
            details TEXT, 
            notes TEXT DEFAULT '', 
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    """)

    # Barkod sütunu kontrolü ve eklenmesi
    try:
        cursor.execute("SELECT barcode FROM inventory LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE inventory ADD COLUMN barcode TEXT")

    # Eski kayıtlara barkod ata
    rows = cursor.execute("SELECT id FROM inventory WHERE barcode IS NULL OR barcode = ''").fetchall()
    if rows:
        for row in rows:
            new_barcode = generate_barcode()
            cursor.execute("UPDATE inventory SET barcode = ? WHERE id = ?", (new_barcode, row[0]))
        conn.commit()

    # 3. Arızalı/Bozuk Envanter
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS defective_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_inventory_id INTEGER,
            original_user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            type TEXT NOT NULL,
            model_name TEXT NOT NULL,
            serial_number TEXT,
            device_name TEXT,
            barcode TEXT,
            quantity INTEGER NOT NULL,
            details TEXT,
            defect_notes TEXT,
            defective_date TEXT NOT NULL,
            FOREIGN KEY (original_user_id) REFERENCES users (id)
        );
    """)
    
    try:
        cursor.execute("SELECT barcode FROM defective_inventory LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE defective_inventory ADD COLUMN barcode TEXT")

    try:
        cursor.execute("SELECT notes FROM inventory LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE inventory ADD COLUMN notes TEXT DEFAULT ''")

    # 4. Paylaşılan Nitelikler
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shared_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attribute_name TEXT NOT NULL,
            value TEXT UNIQUE NOT NULL
        );
    """)

    # 5. Modeller
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT UNIQUE NOT NULL
        );
    """)

    # --- YENİ TABLO: TRANSFER GEÇMİŞİ ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transfer_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_type TEXT NOT NULL,
            model_name TEXT NOT NULL,
            barcode TEXT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            quantity INTEGER NOT NULL,
            transfer_date TEXT NOT NULL,
            FOREIGN KEY (from_user_id) REFERENCES users (id),
            FOREIGN KEY (to_user_id) REFERENCES users (id)
        );
    """)
    # -------------------------------------

    # Varsayılan Kullanıcılar
    try:
        password_admin = b'adminpass'
        hashed_admin = bcrypt.hashpw(password_admin, bcrypt.gensalt()).decode('utf-8')
        password_ahmet = b'1234'
        hashed_ahmet = bcrypt.hashpw(password_ahmet, bcrypt.gensalt()).decode('utf-8')

        if not cursor.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", 
                           ('admin', hashed_admin, 1))
        
        if not cursor.execute("SELECT id FROM users WHERE username='ahmet'").fetchone():
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", 
                           ('ahmet', hashed_ahmet, 0))

        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.close()

with app.app_context():
    init_db()

# -----------------
# USER MODELİ
# -----------------
class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        user_row = conn.execute("SELECT id, username, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        if user_row:
            return User(id=user_row['id'], username=user_row['username'], is_admin=user_row['is_admin'])
        return None
    
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user_row = conn.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username=?", (username,)).fetchone()
        return user_row

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# -----------------
# YARDIMCI FONKSİYONLAR
# -----------------
def is_admin():
    if not current_user.is_admin:
        flash('Bu sayfaya erişim yetkiniz yoktur.', 'danger')
        return redirect(url_for('home'))
    return None

def get_user_id_by_username(username):
    conn = get_db_connection()
    user_row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    return user_row['id'] if user_row else None

def get_username_by_user_id(user_id):
    conn = get_db_connection()
    user_row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    return user_row['username'] if user_row else None

def get_processed_inventory(target_username):
    conn = get_db_connection()
    user_id = get_user_id_by_username(target_username)
    
    if not user_id:
        return []

    inventory = conn.execute("""
        SELECT i.*, u.username 
        FROM inventory i
        JOIN users u ON i.user_id = u.id
        WHERE i.user_id = ?
    """, (user_id,)).fetchall()
    
    processed_inventory = []
    for item in inventory:
        item_dict = dict(item)
        if item_dict.get('details'):
            try:
                item_dict['details'] = json.loads(item_dict['details'])
            except json.JSONDecodeError:
                item_dict['details'] = {'Hata': 'Detaylar JSON formatında değil.'}
        else:
            item_dict['details'] = {}
        
        processed_inventory.append(item_dict)

    return processed_inventory

def get_all_users(include_admin=True):
    conn = get_db_connection()
    where_clause = "WHERE is_admin = 0" if not include_admin else "" 
    users = conn.execute(f"SELECT id, username, is_admin FROM users {where_clause} ORDER BY username").fetchall()
    return [dict(user) for user in users]

def get_all_shared_attributes_for_view():
    conn = get_db_connection()
    attributes_list = conn.execute("SELECT attribute_name, value FROM shared_attributes ORDER BY attribute_name, value").fetchall()
    
    shared_attribute_values_dict = {}
    for attr in attributes_list:
        name = attr['attribute_name']
        value = attr['value']
        if name not in shared_attribute_values_dict:
            shared_attribute_values_dict[name] = []
        shared_attribute_values_dict[name].append(value)
        
    all_possible_attribute_names = set()
    for attrs in SHARED_ATTRIBUTE_TYPES.values():
        all_possible_attribute_names.update(attrs)
    all_possible_attribute_names.discard("Marka/Model") 
    attribute_names_for_form = sorted(list(all_possible_attribute_names))
    
    return [dict(attr) for attr in attributes_list], shared_attribute_values_dict, attribute_names_for_form

def get_all_model_names():
    conn = get_db_connection()
    models = conn.execute("SELECT model_name FROM models ORDER BY model_name").fetchall()
    return [model['model_name'] for model in models]

def get_filtered_inventory(filters):
    conn = get_db_connection()
    query = """
        SELECT i.*, u.username
        FROM inventory i
        JOIN users u ON i.user_id = u.id
        WHERE 1=1
    """
    params = []
    
    if not current_user.is_admin:
        query += " AND i.user_id = ?"
        params.append(current_user.id)

    if filters:
        item_type = filters.get('item_type')
        if item_type:
            query += " AND i.type = ?"
            params.append(item_type)
        
        model_name = filters.get('model_name')
        if model_name:
            query += " AND i.model_name = ?"
            params.append(model_name)
        
        barcode = filters.get('barcode')
        if barcode:
             query += " AND i.barcode LIKE ?"
             params.append(f'%{barcode}%')

        detail_filters = {}
        for key, value in filters.items():
            if value and key not in ['item_type', 'model_name', 'barcode', 'csrf_token']:
                detail_filters[key] = value
                
        for detail_name, detail_value in detail_filters.items():
            json_fragment = f'"{detail_name}": "{detail_value}"'
            query += " AND i.details LIKE ?"
            params.append(f'%{json_fragment}%')
            
    query += " ORDER BY u.username, i.type"
    
    inventory = conn.execute(query, tuple(params)).fetchall()
    
    processed_inventory = []
    for item in inventory:
        item_dict = dict(item)
        if item_dict.get('details'):
            try:
                item_dict['details'] = json.loads(item_dict['details'])
            except json.JSONDecodeError:
                item_dict['details'] = {}
        processed_inventory.append(item_dict)

    return processed_inventory

def create_excel_report(inventory_data, report_name):
    if not inventory_data:
        return None 

    columns = [
        "Kullanıcı", "Kategori", "Tip", "Model", "Barkod", "Adet", "Notlar", "Özellikler" 
    ]
    
    report_list = []
    for item in inventory_data:
        details_str = ", ".join(item['details'].values()) if item.get('details') else "-"

        report_list.append([
            item.get('username', get_username_by_user_id(item['user_id'])), 
            item['category'], 
            item['type'], 
            item['model_name'], 
            item.get('barcode', '-'), 
            item['quantity'],
            item['notes'] or "-", 
            details_str 
        ])

    df = pd.DataFrame(report_list, columns=columns)
    
    output = BytesIO()
    df.to_excel(output, index=False, sheet_name='Envanter')
    
    output.seek(0)
    now = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{report_name}_{now}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

# -----------------
# LOG FONKSİYONU (YENİ)
# -----------------
def log_transfer(conn, item_type, model_name, barcode, from_user_id, to_user_id, quantity):
    """Transfer işlemini tarihçeye kaydeder."""
    try:
        conn.execute("""
            INSERT INTO transfer_history (item_type, model_name, barcode, from_user_id, to_user_id, quantity, transfer_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (item_type, model_name, barcode, from_user_id, to_user_id, quantity, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    except Exception as e:
        print(f"Loglama hatası: {e}")

# -----------------
# ROTLAR (Routes)
# -----------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8') 
        
        user_row = User.get_by_username(username)

        if user_row and bcrypt.checkpw(password, user_row['password_hash'].encode('utf-8')):
            user = User(id=user_row['id'], username=user_row['username'], is_admin=user_row['is_admin'])
            login_user(user)
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Kullanıcı adı veya şifre yanlış.', 'danger')

    return render_template('login.html', title='Kullanıcı Girişi')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    if current_user.is_admin:
        return redirect(url_for('admin_users')) 
    else:
        processed_inventory = get_processed_inventory(current_user.username)
        _, shared_attribute_values_dict, _ = get_all_shared_attributes_for_view() 
        model_names = get_all_model_names()
        users_for_transfer = get_all_users(include_admin=False) 
        
        conn = get_db_connection()
        user_details = conn.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()
        
        return render_template('inventory.html', 
                               title=f'{current_user.username.capitalize()} Envanteri', 
                               inventory=processed_inventory, 
                               is_admin_view=False, 
                               categories=CATEGORIES, 
                               SHARED_ATTRIBUTE_TYPES=SHARED_ATTRIBUTE_TYPES, 
                               shared_attribute_values=shared_attribute_values_dict,
                               model_names=model_names,
                               users_for_transfer=users_for_transfer, 
                               target_user=current_user.username,
                               target_user_id=current_user.id,
                               user_details=user_details)

@app.route('/inventory/<target_user>', methods=['GET'])
@login_required
def manage_inventory(target_user):
    admin_check = is_admin()
    if admin_check: return admin_check 

    processed_inventory = get_processed_inventory(target_user)
    
    _, shared_attribute_values_dict, _ = get_all_shared_attributes_for_view()
    model_names = get_all_model_names()
    users_for_transfer = get_all_users(include_admin=False) 
    
    target_user_id = get_user_id_by_username(target_user)

    conn = get_db_connection()
    user_details = conn.execute("SELECT * FROM users WHERE id=?", (target_user_id,)).fetchone()

    return render_template('inventory.html',
                           title=f'{target_user.capitalize()} Envanter Yönetimi',
                           inventory=processed_inventory,
                           is_admin_view=True,
                           categories=CATEGORIES, 
                           SHARED_ATTRIBUTE_TYPES=SHARED_ATTRIBUTE_TYPES, 
                           shared_attribute_values=shared_attribute_values_dict,
                           model_names=model_names,
                           users_for_transfer=users_for_transfer, 
                           target_user=target_user,
                           target_user_id=target_user_id,
                           user_details=user_details)

@app.route('/inventory/add', methods=['POST'])
@login_required
def add_inventory():
    target_username = request.form.get('target_user')
    if current_user.is_admin and target_username:
        user_id = get_user_id_by_username(target_username)
        if not user_id:
            flash('Hedef kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('admin_users'))
    else:
        user_id = current_user.id
        target_username = current_user.username

    category = request.form.get('category')
    item_type = request.form.get('item_type')
    model_name = request.form.get('model_name')
    quantity = request.form.get('quantity')
    notes = request.form.get('notes', '').strip() 
    
    details = {}
    required_attrs = SHARED_ATTRIBUTE_TYPES.get(item_type, [])
    
    for attr_name in required_attrs:
        if attr_name != "Marka/Model":
            if attr_name == "Kartuş Sayısı":
                cartridge_count = request.form.get(attr_name, 0)
                details[attr_name] = cartridge_count
                for i in range(1, int(cartridge_count) + 1):
                    cartridge_model_key = f"Toner/Kartuş Modeli {i}"
                    cartridge_model_value = request.form.get(cartridge_model_key)
                    if cartridge_model_value:
                        details[cartridge_model_key] = cartridge_model_value
            else:
                value = request.form.get(attr_name)
                if value:
                    details[attr_name] = value

    if category and item_type and model_name and quantity:
        conn = get_db_connection()
        try:
            details_json = json.dumps(details, ensure_ascii=False) 
            barcode = generate_barcode()

            conn.execute("""
                INSERT INTO inventory (user_id, category, type, model_name, barcode, quantity, details, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, category, item_type, model_name, barcode, int(quantity), details_json, notes))
            conn.commit()
            flash(f'Envanter öğesi başarıyla eklendi. Barkod: {barcode}', 'success')
        except Exception as e:
            flash(f'Ekleme sırasında bir hata oluştu: {e}', 'danger')
    else:
        flash('Zorunlu alanlar doldurulmalıdır (Kategori, Tip, Model, Adet).', 'danger')
    
    if current_user.is_admin and target_username != current_user.username:
        return redirect(url_for('manage_inventory', target_user=target_username))
    else:
        return redirect(url_for('home'))

@app.route('/inventory/edit/<int:item_id>', methods=['POST'])
@login_required
def edit_inventory_item(item_id):
    conn = get_db_connection()
    item = conn.execute("SELECT user_id, type FROM inventory WHERE id=?", (item_id,)).fetchone()

    target_user = request.form.get('target_user') 
    
    if not item:
        flash('Düzenlenecek envanter öğesi bulunamadı.', 'danger')
        return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin and target_user else url_for('home'))
        
    if not current_user.is_admin and item['user_id'] != current_user.id:
        flash('Bu öğeyi düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('home'))
        
    try:
        quantity = int(request.form.get('quantity', 0))
        notes = request.form.get('notes', '').strip()
        item_type = item['type']
        
        details = {}
        required_attrs = SHARED_ATTRIBUTE_TYPES.get(item_type, [])
        for attr_name in required_attrs:
            if attr_name != "Marka/Model":
                value = request.form.get(f'edit_attr_{attr_name}')
                if value:
                    details[attr_name] = value

        if quantity <= 0:
            flash('Adet pozitif bir sayı olmalıdır.', 'danger')
            raise ValueError("Adet 0 veya altı olamaz.")
        
        details_json = json.dumps(details, ensure_ascii=False)

        conn.execute("""
            UPDATE inventory SET quantity=?, notes=?, details=?
            WHERE id=?
        """, (quantity, notes, details_json, item_id))
        conn.commit()
        flash(f"'{item['type']}' öğesi başarıyla güncellendi.", 'success')

    except ValueError:
        pass 
    except Exception as e:
        flash(f'Güncelleme sırasında bir hata oluştu: {e}', 'danger')

    if current_user.is_admin and target_user and target_user != current_user.username:
        return redirect(url_for('manage_inventory', target_user=target_user))
    else:
        return redirect(url_for('home'))


@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_inventory_item(item_id):
    conn = get_db_connection()
    item = conn.execute("SELECT user_id FROM inventory WHERE id=?", (item_id,)).fetchone()
    
    if item:
        if current_user.is_admin or item['user_id'] == current_user.id:
            try:
                conn.execute("DELETE FROM inventory WHERE id=?", (item_id,))
                conn.commit()
                flash('Envanter öğesi başarıyla silindi.', 'success')
            except Exception as e:
                flash(f'Silme sırasında bir hata oluştu: {e}', 'danger')
        else:
            flash('Bu öğeyi silme yetkiniz yok.', 'danger')
    else:
        flash('Silinecek envanter öğesi bulunamadı.', 'danger')

    target_user = request.form.get('target_user')
    if current_user.is_admin and target_user and target_user != current_user.username:
        return redirect(url_for('manage_inventory', target_user=target_user))
    else:
        return redirect(url_for('home'))

@app.route('/inventory/transfer/<int:item_id>', methods=['POST'])
@login_required
def transfer_item(item_id):
    """Admin: Bir envanter öğesini bir kullanıcıdan diğerine aktarır."""
    admin_check = is_admin()
    if admin_check: return admin_check

    new_username = request.form.get('new_user')
    transfer_quantity = int(request.form.get('transfer_quantity', 0))
    current_username = request.form.get('current_user')

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
    
    if not item:
        flash('Aktarılacak envanter öğesi bulunamadı.', 'danger')
        return redirect(url_for('manage_inventory', target_user=current_username))
    
    current_quantity = item['quantity']
    from_user_id = item['user_id'] # Kaynak kullanıcı

    new_user_row = conn.execute("SELECT id, username FROM users WHERE username=?", (new_username,)).fetchone()
    
    if not new_user_row:
        flash(f"Hedef kullanıcı '{new_username}' bulunamadı.", 'danger')
        return redirect(url_for('manage_inventory', target_user=current_username))
    
    new_user_id = new_user_row['id']
    
    if transfer_quantity <= 0 or transfer_quantity > current_quantity:
        flash(f"Geçersiz miktar. Aktarılacak miktar 1 ile {current_quantity} arasında olmalıdır.", 'danger')
        return redirect(url_for('manage_inventory', target_user=current_username))
        
    try:
        final_barcode = item['barcode']

        if transfer_quantity == current_quantity:
            conn.execute("UPDATE inventory SET user_id=? WHERE id=?", (new_user_id, item_id))
            flash(f"Tüm {item['type']} öğesi ({current_username} -> {new_username}) başarıyla aktarıldı.", 'success')
            
        else:
            remaining_quantity = current_quantity - transfer_quantity
            conn.execute("UPDATE inventory SET quantity=? WHERE id=?", (remaining_quantity, item_id))
            
            final_barcode = generate_barcode() # Yeni barkod
            
            conn.execute("""
                INSERT INTO inventory (user_id, category, type, model_name, barcode, quantity, details, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (new_user_id, item['category'], item['type'], item['model_name'], 
                  final_barcode, transfer_quantity, item['details'], item['notes']))
            
            flash(f"{transfer_quantity} adet {item['type']} öğesi ({current_username} -> {new_username}) başarıyla aktarıldı (Yeni Barkod: {final_barcode}).", 'success')
            
        # LOGLAMA
        log_transfer(conn, item['type'], item['model_name'], final_barcode, from_user_id, new_user_id, transfer_quantity)

        conn.commit()

    except Exception as e:
        flash(f"Aktarım sırasında bir hata oluştu: {e}", 'danger')

    return redirect(url_for('manage_inventory', target_user=current_username))

@app.route('/inventory/self_transfer/<int:item_id>', methods=['POST'])
@login_required
def self_transfer_item(item_id):
    """Personel: Kendi envanterindeki bir öğeyi başka bir personele aktarır."""
    if current_user.is_admin:
        flash('Adminler bu rotayı kullanmamalıdır. Lütfen Admin Yönetim sayfasını kullanın.', 'danger')
        return redirect(url_for('home'))
    
    new_username = request.form.get('new_user')
    transfer_quantity = int(request.form.get('transfer_quantity', 0))

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory WHERE id=? AND user_id=?", (item_id, current_user.id)).fetchone()
    
    if not item:
        flash('Aktarılacak envanter öğesi bulunamadı veya size ait değil.', 'danger')
        return redirect(url_for('home'))
    
    current_quantity = item['quantity']
    from_user_id = current_user.id # Kaynak kullanıcı (kendisi)

    new_user_row = conn.execute("SELECT id, username FROM users WHERE username=?", (new_username,)).fetchone()
    
    if not new_user_row or new_user_row['id'] == current_user.id:
        flash(f"Hedef kullanıcı '{new_username}' bulunamadı veya kendiniz olamazsınız.", 'danger')
        return redirect(url_for('home'))
    
    if new_user_row['is_admin']:
        flash(f"Hedef kullanıcı '{new_username}' yöneticidir. Yöneticiye aktarım yapamazsınız.", 'danger')
        return redirect(url_for('home'))

    new_user_id = new_user_row['id']
    
    if transfer_quantity <= 0 or transfer_quantity > current_quantity:
        flash(f"Geçersiz miktar. Aktarılacak miktar 1 ile {current_quantity} arasında olmalıdır.", 'danger')
        return redirect(url_for('home'))
        
    try:
        final_barcode = item['barcode']

        if transfer_quantity == current_quantity:
            conn.execute("UPDATE inventory SET user_id=? WHERE id=?", (new_user_id, item_id))
            flash(f"Tüm {item['type']} öğesi ({current_user.username} -> {new_username}) başarıyla aktarıldı.", 'success')
            
        else:
            remaining_quantity = current_quantity - transfer_quantity
            conn.execute("UPDATE inventory SET quantity=? WHERE id=?", (remaining_quantity, item_id))
            
            final_barcode = generate_barcode() # Yeni barkod
            
            conn.execute("""
                INSERT INTO inventory (user_id, category, type, model_name, barcode, quantity, details, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (new_user_id, item['category'], item['type'], item['model_name'], 
                  final_barcode, transfer_quantity, item['details'], item['notes']))
            
            flash(f"{transfer_quantity} adet {item['type']} öğesi ({current_user.username} -> {new_username}) başarıyla aktarıldı (Yeni Barkod: {final_barcode}).", 'success')
        
        # LOGLAMA
        log_transfer(conn, item['type'], item['model_name'], final_barcode, from_user_id, new_user_id, transfer_quantity)

        conn.commit()

    except Exception as e:
        flash(f"Aktarım sırasında bir hata oluştu: {e}", 'danger')

    return redirect(url_for('home'))

@app.route('/inventory/defective/<int:item_id>', methods=['POST'])
@login_required
def flag_as_defective(item_id):
    defect_quantity = int(request.form.get('defect_quantity', 0))
    defect_notes = request.form.get('defect_notes', '').strip()
    target_user = request.form.get('target_user')
    
    user_id_to_check = get_user_id_by_username(target_user) if current_user.is_admin and target_user else current_user.id
    
    if not user_id_to_check:
        flash('Geçerli bir kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory WHERE id=? AND user_id=?", (item_id, user_id_to_check)).fetchone()
    
    if not item:
        flash('Bozuk olarak işaretlenecek envanter öğesi bulunamadı veya size/hedef kullanıcıya ait değil.', 'danger')
        return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin and target_user else url_for('home'))

    current_quantity = item['quantity']
    
    if defect_quantity <= 0 or defect_quantity > current_quantity:
        flash(f"Geçersiz miktar. Bozuk miktar 1 ile {current_quantity} arasında olmalıdır.", 'danger')
        return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin and target_user else url_for('home'))
        
    try:
        if defect_quantity == current_quantity:
            conn.execute("DELETE FROM inventory WHERE id=?", (item_id,))
            
        else:
            remaining_quantity = current_quantity - defect_quantity
            conn.execute("UPDATE inventory SET quantity=? WHERE id=?", (remaining_quantity, item_id))
            
        barcode_to_use = item['barcode'] or generate_barcode()

        conn.execute("""
            INSERT INTO defective_inventory (original_inventory_id, original_user_id, category, type, model_name, barcode, quantity, details, defect_notes, defective_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (item['id'], user_id_to_check, item['category'], item['type'], item['model_name'], 
              barcode_to_use, defect_quantity, item['details'], 
              defect_notes, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
        conn.commit()
        flash(f"{defect_quantity} adet {item['type']} öğesi bozuk olarak işaretlendi ve kaydı alındı.", 'success')

    except Exception as e:
        flash(f"Bozuk olarak işaretleme sırasında bir hata oluştu: {e}", 'danger')

    return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin and target_user else url_for('home'))


@app.route('/inventory/repair/<int:defective_id>', methods=['POST'])
@login_required
def repair_item(defective_id):
    admin_check = is_admin()
    if admin_check: return admin_check

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM defective_inventory WHERE id=?", (defective_id,)).fetchone()
    
    if not item:
        flash('Tamir edilecek cihaz kaydı bulunamadı.', 'danger')
        return redirect(url_for('admin_defective_items'))
        
    try:
        new_username = request.form.get('new_user')
        repair_quantity = int(request.form.get('repair_quantity', 0))
        
        if not new_username:
            flash("Yeni bir kullanıcı seçmelisiniz.", 'danger')
            return redirect(url_for('admin_defective_items'))
            
        new_user_row = conn.execute("SELECT id FROM users WHERE username=?", (new_username,)).fetchone()
        if not new_user_row:
            flash(f"'{new_username}' adında bir kullanıcı bulunamadı.", 'danger')
            return redirect(url_for('admin_defective_items'))
            
        new_user_id = new_user_row['id']
        current_defective_quantity = item['quantity']
        
        if repair_quantity <= 0 or repair_quantity > current_defective_quantity:
            flash(f"Geçersiz miktar. Tamir edilecek miktar 1 ile {current_defective_quantity} arasında olmalıdır.", 'danger')
            return redirect(url_for('admin_defective_items'))

        if repair_quantity < current_defective_quantity:
            remaining_quantity = current_defective_quantity - repair_quantity
            conn.execute("UPDATE defective_inventory SET quantity=? WHERE id=?", (remaining_quantity, defective_id))
        else:
            conn.execute("DELETE FROM defective_inventory WHERE id=?", (defective_id,))
        
        conn.execute("""
            INSERT INTO inventory (user_id, category, type, model_name, barcode, quantity, details, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (new_user_id, item['category'], item['type'], item['model_name'], 
              item['barcode'], repair_quantity, item['details'], 
              f"TAMİR EDİLDİ - Önceki arıza notu: {item['defect_notes']}"))
        
        conn.commit()
        flash(f"{repair_quantity} adet '{item['type']}' cihazı tamir edilerek '{new_username}' kullanıcısına zimmetlendi.", 'success')

    except Exception as e:
        flash(f"İşlem sırasında bir hata oluştu: {e}", 'danger')
        
    return redirect(url_for('admin_defective_items'))

@app.route('/admin/defective_inventory', methods=['GET'])
@login_required
def admin_defective_items():
    admin_check = is_admin()
    if admin_check: return admin_check

    conn = get_db_connection()
    defective_items = conn.execute("""
        SELECT di.*, u.username as original_username
        FROM defective_inventory di
        JOIN users u ON di.original_user_id = u.id
        ORDER BY di.defective_date DESC
    """).fetchall()

    processed_defective = []
    for item in defective_items:
        item_dict = dict(item)
        if item_dict.get('details'):
            try:
                item_dict['details'] = json.loads(item_dict['details'])
            except json.JSONDecodeError:
                item_dict['details'] = {}
        processed_defective.append(item_dict)
    
    users_for_transfer = get_all_users(include_admin=False)

    return render_template('admin_defective_inventory.html',
                           title='Arızalı/Bozuk Envanter',
                           defective_items=processed_defective,
                           users_for_transfer=users_for_transfer)

@app.route('/export/inventory', methods=['GET'])
@login_required
def export_inventory():
    target_user = request.args.get('target_user')
    
    if current_user.is_admin and target_user:
        inventory_data = get_processed_inventory(target_user)
        report_name = f"{target_user.capitalize()}_Envanter_Raporu"
    elif not current_user.is_admin:
        target_user = current_user.username
        inventory_data = get_processed_inventory(target_user)
        report_name = f"{target_user.capitalize()}_Envanter_Raporu"
    else:
        flash("Aktarım için geçerli bir kullanıcı belirtilmedi.", 'danger')
        return redirect(url_for('home'))

    if not inventory_data:
        flash("Aktarılacak envanter verisi bulunamadı.", 'warning')
        return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin else url_for('home'))

    return create_excel_report(inventory_data, report_name)

@app.route('/export/search', methods=['GET'])
@login_required
def export_search_results():
    filters = {k: v for k, v in request.args.items() if v}
    filtered_inventory = get_filtered_inventory(filters)
    
    if not filtered_inventory:
        flash("Aktarılacak sorgu sonucu bulunamadı.", 'warning')
        return redirect(url_for('inventory_search', **filters))
        
    report_name = "Gelişmiş_Sorgu_Raporu"
    
    return create_excel_report(filtered_inventory, report_name)

@app.route('/inventory/zimmet_form', methods=['POST'])
@login_required
def generate_zimmet_form():
    item_ids_str = request.form.get('selected_items')
    target_user_id = request.form.get('target_user_id') 
    
    if not item_ids_str or not target_user_id:
        flash('Zimmet formu oluşturmak için öğe seçmeli ve kullanıcı bilgisi belirtmelisiniz.', 'danger')
        target_user = request.form.get('target_user')
        return redirect(url_for('manage_inventory', target_user=target_user) if current_user.is_admin and target_user else url_for('home'))

    try:
        item_ids = [int(id) for id in item_ids_str.split(',') if id.isdigit()]
    except:
        flash('Geçersiz öğe kimlikleri.', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    
    user_row = conn.execute("SELECT username, department, title FROM users WHERE id=?", (target_user_id,)).fetchone()
    if not user_row:
        flash('Hedef kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('home'))
    
    query = "SELECT * FROM inventory WHERE id IN ({}) AND user_id = ?".format(','.join(['?'] * len(item_ids)))
    
    items = conn.execute(query, item_ids + [target_user_id]).fetchall()
    
    if not items or len(items) != len(item_ids):
        flash('Seçilen öğelerin tamamı bulunamadı veya bu kullanıcıya ait olmayan öğeler seçildi.', 'danger')
        return redirect(url_for('home'))

    zimmet_items = []
    for item in items:
        item_dict = dict(item)
        if item_dict.get('details'):
            try:
                item_dict['details'] = json.loads(item_dict['details'])
            except json.JSONDecodeError:
                item_dict['details'] = {}
        zimmet_items.append(item_dict)

    current_date = datetime.now().strftime('%d.%m.%Y')

    return render_template('zimmet_form.html',
                           title=f"{user_row['username'].capitalize()} Zimmet Formu",
                           user_details=user_row,
                           zimmet_items=zimmet_items,
                           current_date=current_date)

# --- YENİ EKLENEN BARKOD ROTASI ---
@app.route('/inventory/print_barcodes', methods=['POST'])
@login_required
def print_barcodes():
    item_ids_str = request.form.get('selected_items')
    
    if not item_ids_str:
        flash('Barkod yazdırmak için en az bir öğe seçmelisiniz.', 'danger')
        return redirect(url_for('home'))

    try:
        item_ids = [int(id) for id in item_ids_str.split(',') if id.isdigit()]
    except:
        flash('Geçersiz öğe seçimi.', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    
    # Seçilen ID'lere göre ürünleri çekiyoruz
    query = "SELECT * FROM inventory WHERE id IN ({})".format(','.join(['?'] * len(item_ids)))
    items = conn.execute(query, item_ids).fetchall()
    
    # Sözlük yapısına çevir
    barcode_items = []
    for item in items:
        barcode_items.append(dict(item))

    return render_template('barcode_print.html', items=barcode_items)

@app.route('/admin/users')
@login_required
def admin_users():
    admin_check = is_admin()
    if admin_check: return admin_check
    
    users = get_all_users()
    return render_template('admin_users.html', title='Kullanıcı Yönetimi', users=users)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user_route():
    admin_check = is_admin()
    if admin_check: return admin_check
    
    username = request.form.get('username')
    password_str = request.form.get('password')
    is_admin_flag = 1 if request.form.get('is_admin') else 0

    if username and password_str:
        password = password_str.encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", 
                         (username, hashed_password, is_admin_flag))
            conn.commit()
            flash(f"Kullanıcı '{username}' başarıyla eklendi.", 'success')
        except sqlite3.IntegrityError:
            flash(f"Kullanıcı adı '{username}' zaten mevcut.", 'danger')
        except Exception as e:
            flash(f"Kullanıcı eklenirken bir hata oluştu: {e}", 'danger')
    else:
        flash('Kullanıcı adı ve şifre zorunludur.', 'danger')

    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<username>', methods=['POST'])
@login_required
def delete_user_route(username):
    admin_check = is_admin()
    if admin_check: return admin_check
    
    if username == current_user.username:
        flash("Kendi hesabınızı silemezsiniz.", 'danger')
        return redirect(url_for('admin_users'))
    
    conn = get_db_connection()
    try:
        user_id = get_user_id_by_username(username)
        if user_id:
            conn.execute("DELETE FROM inventory WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            flash(f"Kullanıcı '{username}' ve tüm envanteri başarıyla silindi.", 'success')
        else:
            flash("Silinecek kullanıcı bulunamadı.", 'danger')
    except Exception as e:
        flash(f"Silme işlemi sırasında bir hata oluştu: {e}", 'danger')

    return redirect(url_for('admin_users'))

@app.route('/admin/attributes', methods=['GET', 'POST'])
@login_required
def admin_attributes():
    admin_check = is_admin()
    if admin_check: return admin_check

    if request.method == 'POST':
        attribute_name = request.form.get('attribute_name')
        attribute_value = request.form.get('attribute_value', '').strip()
        
        if attribute_name and attribute_value:
            conn = get_db_connection()
            try:
                conn.execute("INSERT INTO shared_attributes (attribute_name, value) VALUES (?, ?)", 
                             (attribute_name, attribute_value))
                conn.commit()
                flash(f"Nitelik '{attribute_name}' için değer '{attribute_value}' başarıyla eklendi.", 'success')
            except sqlite3.IntegrityError:
                flash(f"Bu değer ('{attribute_value}') bu nitelik ('{attribute_name}') için zaten mevcut.", 'warning')
            except Exception as e:
                flash(f"Ekleme sırasında bir hata oluştu: {e}", 'danger')
        else:
            flash('Nitelik adı ve değeri zorunludur.', 'danger')
            
        return redirect(url_for('admin_attributes'))

    attributes, _, attribute_names_for_form = get_all_shared_attributes_for_view()
    
    printer_attributes = SHARED_ATTRIBUTE_TYPES.get("Printer", [])
    for attr in printer_attributes:
        if attr != "Marka/Model" and attr not in attribute_names_for_form:
            attribute_names_for_form.append(attr)
    attribute_names_for_form.sort()
    
    return render_template('admin_attributes.html', 
                           title='Paylaşılan Özellik Yönetimi', 
                           attributes=attributes,
                           attribute_names=attribute_names_for_form)

@app.route('/admin/models')
@login_required
def admin_models():
    admin_check = is_admin()
    if admin_check: return admin_check

    model_names = get_all_model_names()
    
    return render_template('model_view.html',
                           title='Marka/Model Yönetimi',
                           models=model_names)

@app.route('/admin/add_model', methods=['POST'])
@login_required
def admin_add_model():
    admin_check = is_admin()
    if admin_check: return admin_check

    model_name = request.form.get('model_name', '').strip()

    if model_name:
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO models (model_name) VALUES (?)", (model_name,))
            conn.commit()
            flash(f"Model/Marka adı '{model_name}' başarıyla eklendi.", 'success')
        except sqlite3.IntegrityError:
            flash(f"Model/Marka adı '{model_name}' zaten mevcut.", 'warning')
        except Exception as e:
            flash(f"Ekleme sırasında bir hata oluştu: {e}", 'danger')
    else:
        flash('Model/Marka adı zorunludur.', 'danger')

    return redirect(url_for('admin_models'))

@app.route('/admin/delete_model/<model_name>', methods=['POST'])
@login_required
def admin_delete_model(model_name):
    admin_check = is_admin()
    if admin_check: return admin_check
    
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM models WHERE model_name=?", (model_name,))
        conn.commit()
        flash(f"Model/Marka adı '{model_name}' başarıyla silindi.", 'success')
    except Exception as e:
        flash(f"Silme işlemi sırasında bir hata oluştu: {e}", 'danger')

    return redirect(url_for('admin_models'))

@app.route('/inventory/search', methods=['GET'])
@login_required
def inventory_search():
    _, shared_attribute_values_dict, _ = get_all_shared_attributes_for_view()
    model_names = get_all_model_names()

    all_filter_attributes = set()
    for attr_list in SHARED_ATTRIBUTE_TYPES.values():
        for attr in attr_list:
            if attr != "Marka/Model":
                all_filter_attributes.add(attr)

    filters = {k: v for k, v in request.args.items() if v}

    filtered_inventory = get_filtered_inventory(filters)

    return render_template('inventory_search.html',
                           title='Gelişmiş Envanter Sorgulama',
                           all_item_types=sorted(list(ALL_ITEM_TYPES)),
                           model_names=model_names,
                           shared_attribute_values=shared_attribute_values_dict,
                           all_filter_attributes=sorted(list(all_filter_attributes)),
                           filtered_inventory=filtered_inventory,
                           current_filters=filters,
                           is_admin_view=current_user.is_admin)

@app.route('/update_user_details', methods=['POST'])
@login_required
def update_user_details():
    target_user_id = request.form.get('target_user_id')
    department = request.form.get('department')
    title = request.form.get('title') 
    
    if not current_user.is_admin and int(target_user_id) != current_user.id:
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    try:
        conn.execute("UPDATE users SET department = ?, title = ? WHERE id = ?", 
                     (department, title, target_user_id))
        conn.commit()
        flash('Personel bilgileri başarıyla güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {e}', 'danger')
        
    target_username = get_username_by_user_id(target_user_id)
    if current_user.is_admin and target_username != current_user.username:
        return redirect(url_for('manage_inventory', target_user=target_username))
    else:
        return redirect(url_for('home'))

# --- YENİ ROTA: TRANSFER GEÇMİŞİ ---
@app.route('/admin/transfer_history')
@login_required
def transfer_history():
    admin_check = is_admin()
    if admin_check: return admin_check

    conn = get_db_connection()
    transfers = conn.execute("""
        SELECT th.*, u1.username as from_user, u2.username as to_user
        FROM transfer_history th
        LEFT JOIN users u1 ON th.from_user_id = u1.id
        LEFT JOIN users u2 ON th.to_user_id = u2.id
        ORDER BY th.transfer_date DESC
    """).fetchall()

    return render_template('transfer_history.html', 
                           title='Transfer Geçmişi', 
                           transfers=transfers)

@app.before_request
def before_request():
    pass

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)