# ===== ISIS COMEÇA AQUI =====
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
from datetime import datetime
import hashlib

# Funções utilitárias
def derive_aes_key_from_username(username: str) -> bytes:
    """Cada usuário tem sua própria chave AES gerada automaticamente a partir do nome"""
    return hashlib.sha256(username.encode('utf-8')).digest()

def aes_encrypt(msg: str, chave_aes_bytes: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(chave_aes_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(msg.encode('utf-8')) + padder.finalize()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct, iv

def aes_decrypt(ct: bytes, iv: bytes, chave_aes_bytes: bytes) -> str:
    cipher = Cipher(algorithms.AES(chave_aes_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(padded) + unpadder.finalize()
    return raw.decode('utf-8')

# Função segura para rerun em qualquer versão do Streamlit
def safe_rerun():
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()
    else:
        raise RuntimeError("Nenhum método de rerun disponível no Streamlit")
# ===== ISIS TERMINA AQUI =====


# ===== YASMIN COMEÇA AQUI =====
def rsa_encrypt_public(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_private(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def verificar_funcoes_cripto():         
    print("\n=== Testando AES e RSA ===")
    # Teste AES
    chave_aes = os.urandom(32)
    iv = os.urandom(16)
    texto = "Mensagem secreta teste"
    ct, iv = aes_encrypt(texto, chave_aes)
    print("AES - Criptografado:", base64.b64encode(ct).decode())
    print("AES - Decriptado:", aes_decrypt(ct, iv, chave_aes))
    # Teste RSA
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    chave_publica = chave_privada.public_key()
    mensagem = b"Mensagem com RSA teste"
    mensagem_criptografada = rsa_encrypt_public(chave_publica, mensagem)
    print("RSA - Criptografado:", base64.b64encode(mensagem_criptografada).decode())
    print("RSA - Decriptado:", rsa_decrypt_private(chave_privada, mensagem_criptografada).decode())
# ===== YASMIN TERMINA AQUI =====


# ===== IZA COMEÇA AQUI =====
st.set_page_config(page_title="CriptoFusion", page_icon="icon.png", layout="centered")

st.markdown("""
<style>
html, body {
    translate: no !important;
}
</style>
""", unsafe_allow_html=True)

# Login
if "username" not in st.session_state:
    st.session_state.username = None

if st.session_state.username is None:
    st.title("Proteção Híbrida")
    st.markdown("<h5 style='margin-top:-20px; font-weight: normal;'>Segurança Digital Avançada: AES & RSA</h5>", unsafe_allow_html=True)
    st.subheader("👋 Bem-vindo! Identifique-se para iniciar a demonstração")

    st.markdown("""
        <style>
        div.stTextInput > label {
            color: #c1c1c1; 
            font-weight: bold; 
            font-size: 16px;  
        }
        </style>
    """, unsafe_allow_html=True)

    nome = st.text_input("Digite seu nome para entrar no app:")

    col1, col2 = st.columns([8, 1])
    with col1: st.write("")  
    with col2: entrar = st.button("Entrar")

    if entrar:
        if nome.strip() == "":
            st.error("Por favor, digite seu nome para continuar.")
        else:
            st.session_state.username = nome.strip()
            st.success(f"Olá, {st.session_state.username}! Bem-vindo(a).")
            safe_rerun()
# ===== IZA TERMINA AQUI =====


# ===== CAUÃ COMEÇA AQUI =====
elif st.session_state.username:

    if 'mostrar_decripto' not in st.session_state: st.session_state['mostrar_decripto'] = False
    if 'mostrar_saida' not in st.session_state: st.session_state['mostrar_saida'] = False

    st.title(f"CriptoFusion - Proteção Híbrida")
    st.markdown("<h5 style='margin-top:-20px; font-weight: normal;'>Segurança Digital Avançada: AES & RSA</h5>", unsafe_allow_html=True)
    st.markdown(f"<p style='margin-top:-10px; color: #fff;'>Bem-vindo(a) <strong>{st.session_state.username}!</strong></p>", unsafe_allow_html=True)
    st.markdown("<h6 style='color: #c1c1c1; font-weight: normal;'>Implementação de segurança digital através da união entre<br>criptografia simétrica e assimétrica.</h6>", unsafe_allow_html=True)

    if 'private_key' not in st.session_state:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        st.session_state['private_key'] = private_key
        st.session_state['public_key'] = private_key.public_key()

    with st.expander("Instruções rápidas"):
        st.write("""
- Digite uma mensagem (até 128 caracteres).
- A chave AES é gerada automaticamente a partir do seu nome (login).
- O app faz: AES para cifrar a mensagem e RSA para cifrar a chave AES.
- Baixe o pacote cifrado para estudo ou demonstração.
""")

    st.markdown("<h6 style='margin-bottom: -150px;'>Entrada:</h6>", unsafe_allow_html=True)
    st.markdown("""
        <style>
        div.stTextArea > textarea { color: #c1c1c1; }
        </style>
    """, unsafe_allow_html=True)

    mensagem = st.text_area("Mensagem (máx 128 caracteres):", max_chars=128, height=120)
    chave_derived_preview = hashlib.sha256(st.session_state.username.encode('utf-8')).hexdigest()[:24]
    st.info(f"Chave AES derivada (preview): {chave_derived_preview}... (gerada a partir do seu nome)")

    col1, col2 = st.columns([1,1])
    with col1: btn_cripto = st.button("Criptografar")
    with col2: st.write("")

    if btn_cripto:
        if not mensagem:
            st.error("Por favor, digite a mensagem.")
        else:
            try:
                chave_aes_bytes = derive_aes_key_from_username(st.session_state.username)
                with st.spinner("Criptografando (AES + RSA)..."):
                    ct, iv = aes_encrypt(mensagem, chave_aes_bytes)
                    chave_cifrada = rsa_encrypt_public(st.session_state['public_key'], chave_aes_bytes)

                st.session_state['ct_b64'] = b64(ct)
                st.session_state['iv_b64'] = b64(iv)
                st.session_state['chave_cifrada_b64'] = b64(chave_cifrada)
                st.session_state['ultima_msg'] = mensagem
                st.session_state['timestamp'] = datetime.utcnow().isoformat() + "Z"
                st.session_state['mostrar_saida'] = True
                st.session_state['mostrar_decripto'] = False
                safe_rerun()
            except Exception as e:
                st.exception(f"Erro durante a criptografia: {e}")

    if st.session_state.get('mostrar_saida'):
        st.markdown("### Etapas da demonstração")
        st.markdown("<h6 style='margin-bottom:10px; padding:0; color: #c1c1c1; font-weight: normal;'>&#9679; Mensagem criptografada (AES + RSA)</h6>", unsafe_allow_html=True)

        if st.session_state.get('ct_b64') and not st.session_state.get('mostrar_decripto'):
            st.success("Mensagem criptografada com sucesso")

        with st.expander("Saída (pacote cifrado)"):
            st.markdown("**Ciphertext (AES, Base64)**")
            st.code(st.session_state['ct_b64'], language="text")
            st.markdown("**IV (Base64)**")
            st.code(st.session_state['iv_b64'], language="text")
            st.markdown("**Chave AES cifrada com RSA (Base64)**")
            st.code(st.session_state['chave_cifrada_b64'], language="text")

        package = {
            "ciphertext": st.session_state['ct_b64'],
            "iv": st.session_state['iv_b64'],
            "aes_key_encrypted": st.session_state['chave_cifrada_b64'],
            "meta": {
                "timestamp_utc": st.session_state['timestamp'],
                "user": st.session_state.username
            }
        }

        col1, col2 = st.columns([4,1])
        with col1:
            st.download_button("Baixar pacote cifrado (JSON)", data=json.dumps(package, ensure_ascii=False, indent=2), file_name="pacote_cifrado.json")
        with col2:
            btn_decripto = st.button("Descriptografar", key="descripto_pacote")

        if btn_decripto:
            if not st.session_state.get('ct_b64'):
                st.warning("Ainda não há dados cifrados nesta sessão. Primeiro criptografe uma mensagem.")
            else:
                try:
                    with st.spinner("Descriptografando..."):
                        ct = from_b64(st.session_state['ct_b64'])
                        iv = from_b64(st.session_state['iv_b64'])
                        chave_cifrada = from_b64(st.session_state['chave_cifrada_b64'])
                        chave_aes_bytes = rsa_decrypt_private(st.session_state['private_key'], chave_cifrada)
                        mensagem_recuperada = aes_decrypt(ct, iv, chave_aes_bytes)

                    st.success("Descriptografia concluída")
                    st.session_state['mostrar_saida'] = False
                    st.session_state['mostrar_decripto'] = True

                    st.markdown("<h6 style='margin-bottom:10px; padding:0; color: #c1c1c1; font-weight: normal;'>&#9679; Mensagem Descriptografada </h6>", unsafe_allow_html=True)

                    with st.expander("Resultados da descriptografia"):
                        st.markdown("**Chave AES recuperada (hex)**")
                        st.code(chave_aes_bytes.hex())
                        st.markdown("**Mensagem original recuperada**")
                        st.code(mensagem_recuperada)
                except Exception as e:
                    st.exception(f"Erro durante a descriptografia: {e}")

    col1, col2 = st.columns([10, 1])
    with col1: st.write("")  
    with col2: sair = st.button("Sair")
    if sair:
        st.session_state.username = None
        safe_rerun()
# ===== CAUÃ TERMINA AQUI =====


# Roda a função no terminal
if __name__ == "__main__":
    verificar_funcoes_cripto()
