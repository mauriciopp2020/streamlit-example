# streamlit run web.py
# 
# python -m streamlit run web.py


import numpy as np
import pandas as pd
import streamlit as st
import math
import matplotlib.pyplot as plt
import requests
import hashlib


def calculate_entropy(password):
    total_characters = len(password)
    character_count = {}
    for char in password:
        if char in character_count:
            character_count[char] += 1
        else:
            character_count[char] = 1

    entropy = 0
    for count in character_count.values():
        probability = count / total_characters
        entropy -= probability * math.log2(probability)

    entropy_bits = math.ceil(entropy * total_characters)

    return entropy_bits

def check_password_compromised(password):
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    password_prefix = password_hash[:5]
    password_suffix = password_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{password_prefix}"
    response = requests.get(url)
    passwords = response.text.split('\n')
    for p in passwords:
        if password_suffix in p:
            return True
    return False

def format_occurrence(value):
    if value:
        return '✓'
    else:
        return '✗'

def validate_password(password, name, lastname, cpf):
    entropy_bits = calculate_entropy(password)

    # Verificação de engenharia social
    social_engineering = name.lower() in password.lower() or lastname.lower() in password.lower() or cpf in password
    if social_engineering and (name.lower() in password.lower() or lastname.lower() in password.lower() or cpf in password): 
        return 'Senha contém informações pessoais. Por favor, escolha outra senha.', 'red', entropy_bits, False

               
       
    else:
        compromised = check_password_compromised(password)
        if compromised is None:
            return 'Erro ao verificar a senha. Tente novamente mais tarde.', 'red', entropy_bits, False
        elif compromised:
            return 'Senha comprometida! Por favor, escolha outra senha.', 'red', entropy_bits, True
        elif entropy_bits >= 60:
            return 'Senha forte', 'green', entropy_bits, False
        elif entropy_bits >= 40:
            return 'Senha de média segurança', 'orange', entropy_bits, False
        else:
            return 'Senha fraca', 'red', entropy_bits, False



def plot_entropy_chart(entropy_bits):
    labels = ['Entropia']
    values = [entropy_bits]

    fig, ax = plt.subplots(figsize=(6, 3))
    bar_width = 0.1
    ax.bar(labels, values, color='blue', width=bar_width)
    ax.set_ylabel('Valor de Entropia (bits)')
    ax.set_title('Análise de Entropia da Senha')
    ax.axhline(y=60, color='green', linestyle='--', linewidth=1, label='Limite mínimo para senha forte (60 bits)')
    ax.axhline(y=40, color='orange', linestyle='--', linewidth=1, label='Limite mínimo para senha de média segurança (40 bits)')
    ax.legend(fontsize='x-small')

    st.pyplot(fig)

def main():
    #
    # st.sidebar.title("Segurança da Informação")
    #st.sidebar.image("logo.png", width=150)

    st.sidebar.image(
    "logo.png",
    use_column_width=True,
    width=300,
    clamp=True
    
)
  
    st.title('Validação de Senha')

    st.markdown('---')

    st.markdown(
    """
    <style>
    .stTextInput input, .stText textarea {
        background-color: #F2F2F2;
        border-color: #C0C0C0;
        border-radius: 5px;
        padding: 10px;
        font-size: 14px;
        color: #333333;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Campos do formulário
    password = st.text_input('Digite sua senha', type='password')
    name = st.text_input('Digite seu nome')
    lastname = st.text_input('Digite seu sobrenome')
    cpf = st.text_input('Digite seu CPF')

    if st.button('Validar'):
        if password:
            result, color, entropy_bits, compromised = validate_password(password, name, lastname, cpf)
            st.markdown(f'**Resultado**: {result}', unsafe_allow_html=True)
            st.markdown(f'<span style="color:{color};font-weight:bold;">{result}</span>', unsafe_allow_html=True)

            if compromised:
                st.warning('Essa senha foi comprometida e aparece em vazamentos de dados. Por favor, escolha outra senha.')
            else:
                st.success('Essa senha não foi encontrada em vazamentos de dados.')

            if not (name.lower() in password.lower() or lastname.lower() in password.lower() or cpf in password):
                data = {
                    'Dados de Engenharia Social': ['Nome', 'Sobrenome', 'CPF'],
                    'Ocorrência na senha': [name.lower() in password.lower(), lastname.lower() in password.lower(), cpf in password]
                }
                df = pd.DataFrame(data)
                df['Ocorrência na senha'] = df['Ocorrência na senha'].apply(format_occurrence)
                st.subheader('Dados de Engenharia Social')
                st.dataframe(df)

                st.markdown('---')

                st.subheader('Análise de Entropia da Senha')
                st.markdown(f'- Entropia: {entropy_bits} bits')
                plot_entropy_chart(entropy_bits)

        else:
            st.warning('Por favor, digite uma senha')

if __name__ == '__main__':
    main()

