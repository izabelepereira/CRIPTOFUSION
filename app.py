# app.py
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

# -----------------------
# Configuração da página
# -----------------------
st.set_page_config(page_title="APS — CriptoFusion (AES + RSA)", page_icon="🔒", layout="centered")

# -----------------------
# Login simples apenas com nome
# -----------------------
if "username" not in st.session_state:
    st.session_state.username = None

if st.session_state.username is None:
    st.title("APS — CriptoFusion")
    st.subheader("👋 Bem-vindo! Identifique-se para iniciar a demonstração")
    nome = st.text_input("Digite seu nome para entrar no app:")
    entrar = st.button("Entrar")
    if entrar and nome.strip() != "":
        st.session_state.username = nome.strip()
        st.success(f"Olá, {st.session_state.username}! Bem-vindo(a).")
    # Streamlit vai atualizar sozinho na próxima execução

else:
    # Sidebar com usuário e logout
    st.sidebar.write(f"👤 Usuário: **{st.session_state.username}**")
    if st.sidebar.button("🚪 Sair"):
        st.session_state.username = None
        st.experimental_rerun()

    # Cabeçalho principal
    st.title(f"APS — CriptoFusion (AES + RSA) — Usuário: {st.session_state.username}")
    st.markdown(
        """
**Tema:** As técnicas criptográficas, conceitos, usos e aplicações — cenário: acesso restrito a navio com lixo tóxico.  
Nesta demo o aplicativo gera a chave AES automaticamente a partir do seu nome (login) para simplificar a apresentação.
"""
    )

    # -----------------------
    # Geração / Persistência das chaves RSA
    # -----------------------
    if 'private_key' not in st.session_state:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        st.session_state['private_key'] = private_key
        st.session_state['public_key'] = public_key

    # -----------------------
    # Funções utilitárias
    # -----------------------
    def derive_aes_key_from_username(username: str) -> bytes:
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

    # -----------------------
    # Inputs UI
    # -----------------------
    st.subheader("🔑 Entrada (para demonstração)")
    with st.expander("Instruções rápidas (clique)"):
        st.write("""
- Digite uma mensagem (até 128 caracteres).
- A chave AES é gerada automaticamente a partir do seu nome (login).
- O app faz: AES para cifrar a mensagem e RSA para cifrar a chave AES.
- Em aula: visualize a saída em Base64 e baixe o pacote cifrado para demonstrar a transmissão segura.
""")

    mensagem = st.text_area("Mensagem (máx 128 caracteres):", max_chars=128, height=120)

    # Mostra a chave derivada (preview)
    chave_derived_preview = hashlib.sha256(st.session_state.username.encode('utf-8')).hexdigest()[:24]
    st.info(f"Chave AES derivada (preview): {chave_derived_preview}... (gerada a partir do seu nome)")

    col1, col2 = st.columns([1,1])
    with col1:
        btn_cripto = st.button("🔒 Criptografar")
    with col2:
        btn_decripto = st.button("🔓 Descriptografar (se houver dados)")

    # -----------------------
    # Criptografar
    # -----------------------
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

                st.success("Mensagem criptografada com sucesso ✅")
                with st.expander("📦 Saída (pacote cifrado)"):
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
                    "meta": {"timestamp_utc": st.session_state['timestamp'], "user": st.session_state.username}
                }
                st.download_button("⬇️ Baixar pacote cifrado (JSON)", data=json.dumps(package, ensure_ascii=False, indent=2), file_name="pacote_cifrado.json")
            except Exception as e:
                st.exception(f"Erro durante a criptografia: {e}")

    # -----------------------
    # Descriptografar
    # -----------------------
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

                st.success("Descriptografia concluída ✅")
                with st.expander("🔓 Resultados da descriptografia"):
                    st.markdown("**Chave AES recuperada (hex)**")
                    st.code(chave_aes_bytes.hex())
                    st.markdown("**Mensagem original recuperada**")
                    st.code(mensagem_recuperada)
            except Exception as e:
                st.exception(f"Erro durante a descriptografia: {e}")
