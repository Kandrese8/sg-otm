import streamlit as st
import sqlite3
import hashlib
import hmac
import secrets
import json
from datetime import datetime
from pathlib import Path
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "sg_otm.db"
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ROLES = ["Administrador de TI", "Supervisor", "Técnico", "Coordinador"]
PRIORITIES = ["Baja", "Media", "Alta", "Crítica"]
MAINTENANCE_TYPES = ["Preventivo", "Correctivo", "Predictivo", "Otro"]
STATUSES = ["Abierta", "En ejecución", "Pendiente de revisión", "En revisión", "Pendiente de cierre", "Cerrada"]

st.set_page_config(page_title="SG-OTM | Mantenimiento", page_icon="🛠️", layout="wide")

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 180_000)
        return hmac.compare_digest(check.hex(), digest_hex)
    except Exception:
        return False

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            identifier TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            supervisor_id INTEGER NOT NULL,
            location TEXT NOT NULL,
            area TEXT NOT NULL,
            equipment TEXT NOT NULL,
            maintenance_type TEXT NOT NULL,
            priority TEXT NOT NULL,
            problem TEXT NOT NULL,
            initial_notes TEXT,
            status TEXT NOT NULL,
            technician_id INTEGER,
            taken_at TEXT,
            started_at TEXT,
            finished_at TEXT,
            submitted_at TEXT,
            supervisor_reviewed_at TEXT,
            coordinator_closed_at TEXT,
            diagnosis TEXT,
            activities TEXT,
            failure_cause TEXT,
            solution TEXT,
            technical_notes TEXT,
            hours REAL,
            materials TEXT,
            tools TEXT,
            recommendations TEXT,
            supervisor_notes TEXT,
            coordinator_notes TEXT,
            attachments TEXT DEFAULT '[]',
            FOREIGN KEY(supervisor_id) REFERENCES users(id),
            FOREIGN KEY(technician_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            user_id INTEGER,
            role TEXT,
            action TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            demo_users = [
                ("Admin", "Sistema", "ADMIN-001", "admin@sgotm.demo", "admin", "Admin123!", "Administrador de TI"),
                ("Sofía", "Supervisora", "SUP-001", "supervisor@sgotm.demo", "supervisor", "Demo123!", "Supervisor"),
                ("Tomás", "Técnico", "TEC-001", "tecnico@sgotm.demo", "tecnico", "Demo123!", "Técnico"),
                ("Camila", "Coordinadora", "COOR-001", "coordinador@sgotm.demo", "coordinador", "Demo123!", "Coordinador"),
            ]
            for first, last, ident, email, username, password, role in demo_users:
                con.execute("""INSERT INTO users
                    (first_name,last_name,identifier,email,username,password_hash,role,active,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,1,?,?)""",
                    (first,last,ident,email,username,hash_password(password),role,now(),now()))

def log_event(order_id, user, action, old_status=None, new_status=None, notes=""):
    with db() as con:
        con.execute("""INSERT INTO events(order_id,user_id,role,action,old_status,new_status,notes,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (order_id, user["id"] if user else None, user["role"] if user else "Sistema",
                     action, old_status, new_status, notes, now()))

def get_users(active_only=False, role=None):
    query = "SELECT * FROM users WHERE 1=1"
    params = []
    if active_only:
        query += " AND active=1"
    if role:
        query += " AND role=?"
        params.append(role)
    query += " ORDER BY first_name, last_name"
    with db() as con:
        return con.execute(query, params).fetchall()

def get_order(order_id):
    with db() as con:
        return con.execute("""SELECT o.*, 
            s.first_name || ' ' || s.last_name AS supervisor_name,
            t.first_name || ' ' || t.last_name AS technician_name
            FROM orders o
            LEFT JOIN users s ON s.id=o.supervisor_id
            LEFT JOIN users t ON t.id=o.technician_id
            WHERE o.id=?""", (order_id,)).fetchone()

def get_orders():
    with db() as con:
        return con.execute("""SELECT o.*,
            s.first_name || ' ' || s.last_name AS supervisor_name,
            t.first_name || ' ' || t.last_name AS technician_name
            FROM orders o
            LEFT JOIN users s ON s.id=o.supervisor_id
            LEFT JOIN users t ON t.id=o.technician_id
            ORDER BY o.id DESC""").fetchall()

def next_code():
    year = datetime.now().year
    with db() as con:
        n = con.execute("SELECT COUNT(*) FROM orders WHERE code LIKE ?", (f"OT-{year}-%",)).fetchone()[0] + 1
    return f"OT-{year}-{n:05d}"

def change_status(order_id, user, new_status, action, notes="", extra_sql="", extra_params=()):
    order = get_order(order_id)
    if not order:
        return
    old_status = order["status"]
    with db() as con:
        if extra_sql:
            con.execute(f"UPDATE orders SET status=?, {extra_sql} WHERE id=?",
                        (new_status, *extra_params, order_id))
        else:
            con.execute("UPDATE orders SET status=? WHERE id=?", (new_status, order_id))
    log_event(order_id, user, action, old_status, new_status, notes)

def create_pdf(order):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.55*inch, leftMargin=0.55*inch,
                            topMargin=0.55*inch, bottomMargin=0.55*inch)
    styles = getSampleStyleSheet()
    story = [Paragraph("SG-OTM — Orden de Trabajo de Mantenimiento", styles["Title"]),
             Paragraph(f"<b>Código:</b> {order['code']} &nbsp;&nbsp; <b>Estado:</b> {order['status']}", styles["Normal"]),
             Spacer(1, 12)]
    rows = [
        ["Campo", "Información"],
        ["Fecha de creación", order["created_at"] or ""],
        ["Inicio de ejecución", order["started_at"] or ""],
        ["Cierre", order["coordinator_closed_at"] or "Pendiente"],
        ["Ubicación", order["location"] or ""],
        ["Área / dependencia", order["area"] or ""],
        ["Equipo / activo", order["equipment"] or ""],
        ["Tipo de mantenimiento", order["maintenance_type"] or ""],
        ["Prioridad", order["priority"] or ""],
        ["Supervisor", order["supervisor_name"] or ""],
        ["Técnico", order["technician_name"] or "Sin asignar"],
        ["Problema reportado", order["problem"] or ""],
        ["Observaciones iniciales", order["initial_notes"] or ""],
        ["Diagnóstico", order["diagnosis"] or ""],
        ["Actividades realizadas", order["activities"] or ""],
        ["Causa de falla", order["failure_cause"] or ""],
        ["Solución aplicada", order["solution"] or ""],
        ["Observaciones técnicas", order["technical_notes"] or ""],
        ["Horas trabajadas", str(order["hours"] or "")],
        ["Repuestos / materiales", order["materials"] or ""],
        ["Herramientas especiales", order["tools"] or ""],
        ["Recomendaciones", order["recommendations"] or ""],
        ["Revisión del supervisor", order["supervisor_notes"] or ""],
        ["Validación del coordinador", order["coordinator_notes"] or ""],
    ]
    safe_rows = []
    for row in rows:
        safe_rows.append([Paragraph(str(x).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br/>"), styles["BodyText"]) for x in row])
    table = Table(safe_rows, colWidths=[1.7*inch, 5.35*inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#16324F")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#C9D2DC")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F3F6F9")]),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Documento generado por SG-OTM el {now()}. Este prototipo no incorpora firma digital certificada.", styles["Italic"]))
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

def require_fields(values):
    return [name for name, value in values.items() if not str(value or "").strip()]

init_db()

if "user" not in st.session_state:
    st.session_state.user = None

st.title("🛠️ SG-OTM")
st.caption("Sistema de Gestión de Órdenes de Trabajo de Mantenimiento")

if st.session_state.user is None:
    left, center, right = st.columns([1, 1.2, 1])
    with center:
        st.subheader("Iniciar sesión")
        with st.form("login_form"):
            username = st.text_input("Usuario", placeholder="Ej. supervisor")
            password = st.text_input("Contraseña", type="password")
            submitted = st.form_submit_button("Ingresar", type="primary", use_container_width=True)
        if submitted:
            with db() as con:
                user = con.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
            if user and user["active"] and verify_password(password, user["password_hash"]):
                st.session_state.user = dict(user)
                st.rerun()
            else:
                st.error("Credenciales incorrectas o usuario inactivo.")
        with st.expander("Credenciales de demostración"):
            st.markdown("""
            | Rol | Usuario | Contraseña |
            |---|---|---|
            | Administrador | `admin` | `Admin123!` |
            | Supervisor | `supervisor` | `Demo123!` |
            | Técnico | `tecnico` | `Demo123!` |
            | Coordinador | `coordinador` | `Demo123!` |
            """)
        st.info("Prototipo académico. Cambia las contraseñas de demostración antes de usarlo con información real.")
    st.stop()

user = st.session_state.user
full_name = f"{user['first_name']} {user['last_name']}"
with st.sidebar:
    st.markdown("### Sesión activa")
    st.write(f"**{full_name}**")
    st.caption(user["role"])
    if st.button("Cerrar sesión", use_container_width=True):
        st.session_state.user = None
        st.rerun()
    st.divider()
    page = st.radio("Navegación", [
        "Panel principal", "Órdenes de trabajo", "Crear orden", "Ejecución técnica",
        "Revisión del supervisor", "Cierre del coordinador", "Historial y búsqueda",
        "Usuarios", "Auditoría"
    ])

role = user["role"]
orders = get_orders()

if page == "Panel principal":
    st.subheader("Panel principal")
    visible = orders
    if role == "Técnico":
        visible = [o for o in orders if o["technician_id"] == user["id"] or o["status"] == "Abierta"]
    elif role == "Supervisor":
        visible = [o for o in orders if o["supervisor_id"] == user["id"]]
    metrics = st.columns(4)
    metrics[0].metric("Órdenes registradas", len(orders))
    metrics[1].metric("Abiertas", sum(o["status"] == "Abierta" for o in orders))
    metrics[2].metric("En ejecución", sum(o["status"] == "En ejecución" for o in orders))
    metrics[3].metric("Cerradas", sum(o["status"] == "Cerrada" for o in orders))
    st.markdown("#### Órdenes recientes")
    if visible:
        st.dataframe([{"Código":o["code"],"Ubicación":o["location"],"Equipo":o["equipment"],
                       "Prioridad":o["priority"],"Estado":o["status"],"Técnico":o["technician_name"] or "—"}
                      for o in visible[:10]], use_container_width=True, hide_index=True)
    else:
        st.info("Todavía no hay órdenes para mostrar.")

elif page == "Crear orden":
    st.subheader("Crear orden de trabajo")
    if role not in ["Supervisor", "Administrador de TI"]:
        st.warning("Esta función está disponible para el Supervisor.")
    else:
        with st.form("create_order"):
            a,b = st.columns(2)
            with a:
                location = st.text_input("Ubicación física *")
                area = st.text_input("Área / dependencia *")
                equipment = st.text_input("Equipo / activo *")
                maintenance_type = st.selectbox("Tipo de mantenimiento", MAINTENANCE_TYPES)
            with b:
                priority = st.selectbox("Prioridad", PRIORITIES, index=1)
                problem = st.text_area("Descripción del problema *")
                initial_notes = st.text_area("Observaciones iniciales")
            ok = st.form_submit_button("Crear orden", type="primary")
        if ok:
            missing = require_fields({"Ubicación":location,"Área":area,"Equipo":equipment,"Descripción":problem})
            if missing:
                st.error("Completa los campos obligatorios: " + ", ".join(missing))
            else:
                code = next_code()
                with db() as con:
                    cur = con.execute("""INSERT INTO orders(code,created_at,supervisor_id,location,area,equipment,
                        maintenance_type,priority,problem,initial_notes,status)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (code,now(),user["id"],location,area,equipment,maintenance_type,priority,problem,initial_notes,"Abierta"))
                    oid = cur.lastrowid
                log_event(oid,user,"Creación de orden",None,"Abierta",f"Orden creada: {code}")
                st.success(f"Orden {code} creada correctamente.")
                st.rerun()

elif page == "Órdenes de trabajo":
    st.subheader("Órdenes de trabajo")
    state_filter = st.selectbox("Filtrar por estado", ["Todos"] + STATUSES)
    search = st.text_input("Buscar por código, ubicación, equipo o descripción")
    filtered = orders
    if role == "Técnico":
        filtered = [o for o in filtered if o["technician_id"] == user["id"] or o["status"] == "Abierta"]
    elif role == "Supervisor":
        filtered = [o for o in filtered if o["supervisor_id"] == user["id"]]
    if state_filter != "Todos":
        filtered = [o for o in filtered if o["status"] == state_filter]
    if search.strip():
        term = search.strip().lower()
        filtered = [o for o in filtered if term in " ".join(str(o[k] or "") for k in ["code","location","equipment","problem","status","technician_name"]).lower()]
    if filtered:
        st.dataframe([{"Código":o["code"],"Creación":o["created_at"],"Ubicación":o["location"],"Área":o["area"],
                       "Equipo":o["equipment"],"Tipo":o["maintenance_type"],"Prioridad":o["priority"],
                       "Técnico":o["technician_name"] or "—","Estado":o["status"]} for o in filtered],
                     use_container_width=True, hide_index=True)
        choice = st.selectbox("Selecciona una orden para ver detalles", [o["id"] for o in filtered],
                              format_func=lambda x: next(o["code"] for o in filtered if o["id"] == x))
        o = get_order(choice)
        with st.expander("Detalle de la orden", expanded=True):
            st.write(f"**{o['code']} · {o['status']}**")
            st.write(f"**Problema:** {o['problem']}")
            st.write(f"**Ubicación / área / equipo:** {o['location']} / {o['area']} / {o['equipment']}")
            st.write(f"**Supervisor:** {o['supervisor_name']} · **Técnico:** {o['technician_name'] or 'Sin asignar'}")
            st.write(f"**Diagnóstico:** {o['diagnosis'] or '—'}")
            st.write(f"**Actividades:** {o['activities'] or '—'}")
            if o["status"] == "Cerrada":
                st.download_button("Descargar PDF final", create_pdf(o), file_name=f"{o['code']}.pdf", mime="application/pdf")
            if role == "Técnico" and o["status"] == "Abierta":
                if st.button("Tomar esta OT", type="primary"):
                    change_status(o["id"],user,"En ejecución","Toma de orden",
                                  f"Tomada por {full_name}", "technician_id=?, taken_at=?, started_at=?", (user["id"],now(),now()))
                    st.success("Orden asignada a tu usuario.")
                    st.rerun()
    else:
        st.info("No hay órdenes que coincidan con los filtros.")

elif page == "Ejecución técnica":
    st.subheader("Ejecución técnica")
    if role != "Técnico":
        st.info("Esta bandeja está destinada al rol Técnico.")
    else:
        mine = [o for o in orders if o["technician_id"] == user["id"] and o["status"] == "En ejecución"]
        if not mine:
            st.info("No tienes órdenes en ejecución. Puedes tomar una orden abierta en 'Órdenes de trabajo'.")
        else:
            selected = st.selectbox("Orden en ejecución", [o["id"] for o in mine],
                                    format_func=lambda x: next(o["code"] for o in mine if o["id"]==x))
            o = get_order(selected)
            with st.form("execution_form"):
                diagnosis = st.text_area("Diagnóstico *", value=o["diagnosis"] or "")
                activities = st.text_area("Actividades realizadas *", value=o["activities"] or "")
                failure_cause = st.text_area("Causa de falla *", value=o["failure_cause"] or "")
                solution = st.text_area("Solución aplicada *", value=o["solution"] or "")
                technical_notes = st.text_area("Observaciones técnicas", value=o["technical_notes"] or "")
                hours = st.number_input("Horas trabajadas *", min_value=0.0, value=float(o["hours"] or 0.0), step=0.5)
                materials = st.text_area("Repuestos y materiales (nombre, cantidad, unidad)", value=o["materials"] or "")
                tools = st.text_area("Herramientas especiales", value=o["tools"] or "")
                recommendations = st.text_area("Recomendaciones", value=o["recommendations"] or "")
                save = st.form_submit_button("Guardar avance")
                submit = st.form_submit_button("Finalizar y enviar a revisión", type="primary")
            if save or submit:
                missing = require_fields({"Diagnóstico":diagnosis,"Actividades":activities,"Causa de falla":failure_cause,
                                          "Solución aplicada":solution,"Horas trabajadas":hours if hours > 0 else ""})
                if submit and missing:
                    st.error("Completa los campos obligatorios: " + ", ".join(missing))
                else:
                    with db() as con:
                        con.execute("""UPDATE orders SET diagnosis=?,activities=?,failure_cause=?,solution=?,technical_notes=?,
                            hours=?,materials=?,tools=?,recommendations=?,finished_at=? WHERE id=? AND technician_id=? AND status='En ejecución'""",
                            (diagnosis,activities,failure_cause,solution,technical_notes,hours,materials,tools,recommendations,
                             now() if submit else o["finished_at"],selected,user["id"]))
                    log_event(selected,user,"Guardado de avance","En ejecución","En ejecución","Datos técnicos actualizados")
                    if submit:
                        change_status(selected,user,"Pendiente de revisión","Envío a revisión","Intervención enviada al supervisor",
                                      "submitted_at=?", (now(),))
                        st.success("Orden enviada al supervisor para revisión.")
                    else:
                        st.success("Avance guardado.")
                    st.rerun()
            st.markdown("#### Adjuntar evidencia")
            uploaded = st.file_uploader("Fotografías o documentos (máx. 10 MB por archivo)", accept_multiple_files=True,
                                        type=["png","jpg","jpeg","pdf","txt","docx","xlsx"])
            if uploaded and st.button("Guardar archivos"):
                saved = []
                total = 0
                for f in uploaded:
                    total += f.size
                    if f.size > 10 * 1024 * 1024:
                        st.error(f"{f.name} supera el límite de 10 MB.")
                        continue
                    safe_name = f"{selected}_{int(datetime.now().timestamp())}_{Path(f.name).name}"
                    path = UPLOAD_DIR / safe_name
                    path.write_bytes(f.getvalue())
                    saved.append({"name":f.name,"path":str(path.name),"type":f.type,"uploaded_at":now(),"user":full_name})
                current = json.loads(o["attachments"] or "[]")
                current.extend(saved)
                with db() as con:
                    con.execute("UPDATE orders SET attachments=? WHERE id=?", (json.dumps(current,ensure_ascii=False),selected))
                log_event(selected,user,"Carga de archivos","En ejecución","En ejecución",", ".join(x["name"] for x in saved))
                st.success(f"Se guardaron {len(saved)} archivo(s).")
                st.rerun()

elif page == "Revisión del supervisor":
    st.subheader("Revisión del supervisor")
    if role not in ["Supervisor", "Administrador de TI"]:
        st.info("Esta bandeja está destinada al Supervisor.")
    else:
        pending = [o for o in orders if o["status"] == "Pendiente de revisión" and (role == "Administrador de TI" or o["supervisor_id"] == user["id"])]
        if not pending:
            st.info("No hay órdenes pendientes de revisión.")
        else:
            selected = st.selectbox("Orden pendiente", [o["id"] for o in pending],
                                    format_func=lambda x: next(o["code"] for o in pending if o["id"]==x))
            o = get_order(selected)
            st.write(f"**Problema:** {o['problem']}")
            st.write(f"**Técnico:** {o['technician_name'] or '—'} · **Horas:** {o['hours'] or 0}")
            st.write(f"**Diagnóstico:** {o['diagnosis'] or '—'}")
            st.write(f"**Actividades:** {o['activities'] or '—'}")
            st.write(f"**Causa:** {o['failure_cause'] or '—'}")
            st.write(f"**Solución:** {o['solution'] or '—'}")
            notes = st.text_area("Observaciones de revisión")
            a,b = st.columns(2)
            if a.button("Aprobar y enviar a cierre", type="primary"):
                change_status(selected,user,"Pendiente de cierre","Aprobación del supervisor",notes,
                              "supervisor_notes=?, supervisor_reviewed_at=?", (notes,now()))
                st.success("Orden enviada al coordinador.")
                st.rerun()
            with b:
                with st.popover("Devolver al técnico"):
                    reason = st.text_area("Motivo obligatorio de devolución", key="supervisor_return")
                    if st.button("Confirmar devolución"):
                        if not reason.strip():
                            st.error("Debes indicar el motivo.")
                        else:
                            change_status(selected,user,"En ejecución","Devolución del supervisor",reason,
                                          "supervisor_notes=?", (reason,))
                            st.success("Orden devuelta al técnico.")
                            st.rerun()

elif page == "Cierre del coordinador":
    st.subheader("Cierre del coordinador")
    if role not in ["Coordinador", "Administrador de TI"]:
        st.info("Esta bandeja está destinada al Coordinador.")
    else:
        pending = [o for o in orders if o["status"] == "Pendiente de cierre"]
        if not pending:
            st.info("No hay órdenes pendientes de cierre.")
        else:
            selected = st.selectbox("Orden pendiente de cierre", [o["id"] for o in pending],
                                    format_func=lambda x: next(o["code"] for o in pending if o["id"]==x))
            o = get_order(selected)
            st.write(f"**{o['code']} · Técnico:** {o['technician_name'] or '—'}")
            st.write(f"**Diagnóstico:** {o['diagnosis'] or '—'}")
            st.write(f"**Actividades:** {o['activities'] or '—'}")
            st.write(f"**Revisión del supervisor:** {o['supervisor_notes'] or 'Sin observaciones'}")
            notes = st.text_area("Observaciones de validación del coordinador")
            a,b = st.columns(2)
            if a.button("Aprobar y cerrar OT", type="primary"):
                change_status(selected,user,"Cerrada","Cierre oficial",notes,
                              "coordinator_notes=?, coordinator_closed_at=?", (notes,now()))
                log_event(selected,user,"Generación de PDF","Cerrada","Cerrada","PDF final disponible para descarga")
                st.success("Orden cerrada. El PDF final está disponible en Órdenes de trabajo e Historial.")
                st.rerun()
            with b:
                with st.popover("Devolver para corrección"):
                    reason = st.text_area("Motivo obligatorio", key="coordinator_return")
                    if st.button("Confirmar devolución al técnico"):
                        if not reason.strip():
                            st.error("Debes indicar el motivo.")
                        else:
                            change_status(selected,user,"En ejecución","Devolución del coordinador",reason,
                                          "coordinator_notes=?", (reason,))
                            st.success("Orden devuelta al técnico.")
                            st.rerun()

elif page == "Historial y búsqueda":
    st.subheader("Historial y búsqueda de órdenes")
    f1,f2,f3 = st.columns(3)
    term = f1.text_input("Código o palabras clave")
    location_filter = f2.text_input("Ubicación")
    status_filter = f3.selectbox("Estado", ["Todos"] + STATUSES)
    f4,f5 = st.columns(2)
    equipment_filter = f4.text_input("Equipo / activo")
    type_filter = f5.selectbox("Tipo de mantenimiento", ["Todos"] + MAINTENANCE_TYPES)
    filtered = orders
    if role == "Técnico":
        filtered = [o for o in filtered if o["technician_id"] == user["id"]]
    elif role == "Supervisor":
        filtered = [o for o in filtered if o["supervisor_id"] == user["id"]]
    if term.strip():
        q = term.strip().lower()
        filtered = [o for o in filtered if q in " ".join(str(o[k] or "") for k in
                    ["code","problem","diagnosis","failure_cause","solution","technical_notes","recommendations","materials"]).lower()]
    if location_filter.strip():
        filtered = [o for o in filtered if location_filter.lower() in (o["location"] or "").lower()]
    if status_filter != "Todos":
        filtered = [o for o in filtered if o["status"] == status_filter]
    if equipment_filter.strip():
        filtered = [o for o in filtered if equipment_filter.lower() in (o["equipment"] or "").lower()]
    if type_filter != "Todos":
        filtered = [o for o in filtered if o["maintenance_type"] == type_filter]
    st.caption(f"{len(filtered)} resultado(s)")
    if filtered:
        st.dataframe([{"Código":o["code"],"Creación":o["created_at"],"Cierre":o["coordinator_closed_at"] or "—",
                       "Ubicación":o["location"],"Equipo":o["equipment"],"Técnico":o["technician_name"] or "—",
                       "Estado":o["status"]} for o in filtered], use_container_width=True, hide_index=True)
        selected = st.selectbox("Detalle / PDF", [o["id"] for o in filtered],
                                format_func=lambda x: next(o["code"] for o in filtered if o["id"]==x), key="history_choice")
        o = get_order(selected)
        if o["status"] == "Cerrada":
            st.download_button("Descargar PDF de la orden", create_pdf(o), file_name=f"{o['code']}.pdf", mime="application/pdf")
        with st.expander("Eventos de la orden"):
            with db() as con:
                events = con.execute("""SELECT e.*, u.first_name || ' ' || u.last_name AS actor
                    FROM events e LEFT JOIN users u ON u.id=e.user_id WHERE e.order_id=? ORDER BY e.id""", (selected,)).fetchall()
            if events:
                st.dataframe([{"Fecha":e["created_at"],"Usuario":e["actor"] or "Sistema","Rol":e["role"],
                               "Acción":e["action"],"Estado anterior":e["old_status"] or "—",
                               "Estado nuevo":e["new_status"] or "—","Observaciones":e["notes"] or ""} for e in events],
                             use_container_width=True, hide_index=True)
            else:
                st.info("Sin eventos registrados.")
    else:
        st.info("No se encontraron órdenes con esos criterios.")

elif page == "Usuarios":
    st.subheader("Gestión de usuarios")
    if role != "Administrador de TI":
        st.warning("Solo el Administrador de TI puede gestionar usuarios.")
    else:
        with st.expander("Crear usuario", expanded=True):
            with st.form("new_user"):
                c1,c2 = st.columns(2)
                first = c1.text_input("Nombre(s) *")
                last = c2.text_input("Apellidos *")
                identifier = c1.text_input("Identificación / código interno *")
                email = c2.text_input("Correo electrónico *")
                username = c1.text_input("Nombre de usuario *")
                password = c2.text_input("Contraseña temporal *", type="password")
                new_role = st.selectbox("Rol *", ROLES)
                create = st.form_submit_button("Crear usuario", type="primary")
            if create:
                missing = require_fields({"Nombre":first,"Apellidos":last,"Identificación":identifier,"Correo":email,"Usuario":username,"Contraseña":password})
                if missing:
                    st.error("Completa: " + ", ".join(missing))
                elif len(password) < 8:
                    st.error("La contraseña debe tener al menos 8 caracteres.")
                else:
                    try:
                        with db() as con:
                            con.execute("""INSERT INTO users(first_name,last_name,identifier,email,username,password_hash,role,active,created_at,updated_at)
                                VALUES(?,?,?,?,?,?,?,1,?,?)""",
                                (first,last,identifier,email,username,hash_password(password),new_role,now(),now()))
                        log_event(None,user,"Creación de usuario",None,None,f"{username} / {new_role}")
                        st.success("Usuario creado.")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("El identificador o nombre de usuario ya existe.")
        users = get_users()
        st.markdown("#### Usuarios registrados")
        st.dataframe([{"Nombre":f"{u['first_name']} {u['last_name']}","Identificación":u["identifier"],
                       "Correo":u["email"],"Usuario":u["username"],"Rol":u["role"],
                       "Estado":"Activo" if u["active"] else "Inactivo","Creación":u["created_at"]} for u in users],
                     use_container_width=True, hide_index=True)
        chosen = st.selectbox("Selecciona un usuario para administrar", [u["id"] for u in users],
                              format_func=lambda x: next(u["username"] for u in users if u["id"]==x))
        target = next(u for u in users if u["id"] == chosen)
        with st.form("edit_user"):
            edit_role = st.selectbox("Cambiar rol", ROLES, index=ROLES.index(target["role"]))
            edit_active = st.checkbox("Usuario activo", value=bool(target["active"]))
            reset_password = st.text_input("Nueva contraseña (opcional)", type="password")
            update = st.form_submit_button("Guardar cambios")
        if update:
            if reset_password and len(reset_password) < 8:
                st.error("La nueva contraseña debe tener al menos 8 caracteres.")
            else:
                with db() as con:
                    con.execute("UPDATE users SET role=?,active=?,updated_at=? WHERE id=?",
                                (edit_role,int(edit_active),now(),chosen))
                    if reset_password:
                        con.execute("UPDATE users SET password_hash=? WHERE id=?",
                                    (hash_password(reset_password),chosen))
                log_event(None,user,"Actualización de usuario",None,None,f"{target['username']}: rol={edit_role}, activo={edit_active}")
                st.success("Cambios guardados.")
                st.rerun()

elif page == "Auditoría":
    st.subheader("Bitácora de auditoría")
    if role != "Administrador de TI":
        st.warning("Solo el Administrador de TI puede consultar la auditoría general.")
    else:
        with db() as con:
            events = con.execute("""SELECT e.*, u.username, o.code FROM events e
                LEFT JOIN users u ON u.id=e.user_id LEFT JOIN orders o ON o.id=e.order_id
                ORDER BY e.id DESC LIMIT 500""").fetchall()
        if events:
            st.dataframe([{"Fecha":e["created_at"],"Usuario":e["username"] or "Sistema","Rol":e["role"],
                           "Acción":e["action"],"OT":e["code"] or "—","Estado anterior":e["old_status"] or "—",
                           "Estado nuevo":e["new_status"] or "—","Resultado / observaciones":e["notes"] or ""} for e in events],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No hay eventos registrados.")

st.divider()
st.caption("SG-OTM · Prototipo académico funcional. Para uso productivo se recomienda base de datos gestionada, almacenamiento persistente de archivos, correo de notificaciones y revisión de seguridad.")
