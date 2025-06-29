import signal
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Función para generar las claves RSA
def generar_claves():
  clave = RSA.generate(4096)
  private_key = clave.export_key()
  public_key = clave.publickey().export_key()
  return private_key, public_key

# Función para cifrar un archivo usando AES + RSA (cifrado híbrido)
def cifrar_archivo(public_key):
  file_path = filedialog.askopenfilename(title="Seleccionar archivo a cifrar", filetypes=[("Text files", "*.txt")])
  if not file_path:
    return

  try:
    with open(file_path, "rb") as file:
      data = file.read()

    session_key = get_random_bytes(32)
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    with open(file_path.replace(".txt", ".rsa"), "wb") as f:
      for x in (encrypted_session_key, cipher_aes.iv, encrypted_data):
        f.write(x)

    messagebox.showinfo("Éxito", "Archivo cifrado exitosamente.")
  except Exception as e:
    messagebox.showerror("Error", f"Ocurrió un error al cifrar el archivo: {e}")

# Función para descifrar un archivo usando AES + RSA (cifrado híbrido)
def descifrar_archivo(private_key, text_widget):
  file_path = filedialog.askopenfilename(title="Seleccionar archivo a descifrar", filetypes=[("RSA files", "*.rsa")])
  if not file_path:
    return

  try:
    with open(file_path, "rb") as file:
      encrypted_session_key = file.read(512)
      iv = file.read(16)
      encrypted_data = file.read()

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

    # Guardar el contenido descifrado en un archivo
    decrypted_file_path = file_path.replace(".rsa", "_decrypted.txt")
    with open(decrypted_file_path, "wb") as f:
      f.write(decrypted_data)

    # Mostrar el contenido descifrado en el widget de texto
    text_widget.config(state=NORMAL)  # Permitir la edición temporalmente
    text_widget.delete(1.0, END)
    text_widget.insert(END, decrypted_data.decode('utf-8', errors='replace').replace('\r\n', '\n'))
    text_widget.config(state=DISABLED)  # Bloquear la edición

    messagebox.showinfo("Éxito", f"Archivo descifrado exitosamente y guardado como {decrypted_file_path}.")
  except Exception as e:
    messagebox.showerror("Error", f"Ocurrió un error al descifrar el archivo: {e}")

# Función para verificar el inicio de sesión
def verificar_login(usuario, contrasena, root, private_key, public_key):
  usuario_correcto = "usuario"
  contrasena_correcta = "1234"

  if usuario.get() == usuario_correcto and contrasena.get() == contrasena_correcta:
    messagebox.showinfo("Inicio de sesión exitoso", "¡Bienvenido al sistema!")
    root.destroy()
    interfaz(public_key, private_key)
  else:
    messagebox.showerror("Error de inicio de sesión", "Usuario o contraseña incorrectos.")

# Función para la interfaz de login
def iniciar_sesion():
  login_window = Toplevel()
  login_window.title("Iniciar sesión")
  login_window.geometry("300x200")

  usuario = StringVar()
  contrasena = StringVar()

  Label(login_window, text="Usuario:").pack(pady=10)
  Entry(login_window, textvariable=usuario).pack(pady=5)
  Label(login_window, text="Contraseña:").pack(pady=10)
  Entry(login_window, textvariable=contrasena, show="*").pack(pady=5)

  Button(login_window, text="Iniciar sesión", command=lambda: verificar_login(usuario, contrasena, login_window, private_key, public_key)).pack(pady=10)
  login_window.mainloop()

# Función para la interfaz gráfica principal
def interfaz(public_key, private_key):
  root = Tk()
  root.title("Aplicación de Cifrado y Descifrado RSA")
  root.geometry("400x400")

  Label(root, text="Bienvenido al sistema de cifrado RSA", font=("Arial", 14)).pack(pady=20)

  menu = Menu(root)
  root.config(menu=menu)

  archivo_menu = Menu(menu)
  menu.add_cascade(label="Opciones", menu=archivo_menu)
  archivo_menu.add_command(label="Cifrar archivo", command=lambda: cifrar_archivo(public_key))
  archivo_menu.add_command(label="Descifrar archivo", command=lambda: descifrar_archivo(private_key, text_widget))
  archivo_menu.add_separator()
  archivo_menu.add_command(label="Salir", command=root.quit)

  Button(root, text="Cifrar archivo", command=lambda: cifrar_archivo(public_key), width=20).pack(pady=10)
  Button(root, text="Descifrar archivo", command=lambda: descifrar_archivo(private_key, text_widget), width=20).pack(pady=10)

  # Widget de texto para mostrar el contenido descifrado
  text_widget = Text(root, wrap=WORD, height=10, width=40)
  text_widget.pack(pady=10)
  text_widget.config(state=DISABLED)  # Bloquear la edición

  # Asegurarse de que el proceso se cierre al cerrar la ventana
  root.protocol("WM_DELETE_WINDOW", root.quit)

  root.mainloop()

if __name__ == "__main__":
  # Manejar la señal de interrupción para cerrar la aplicación correctamente
  signal.signal(signal.SIGINT, signal.SIG_DFL)

  root = Tk()
  root.withdraw()

  private_key, public_key = generar_claves()

  iniciar_sesion()

  root.deiconify()