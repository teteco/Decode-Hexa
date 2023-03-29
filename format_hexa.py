import re

# lê valor hexadecimal
hex_value = input("Digite o valor em hexadecimal: ")

# remove qualquer caracter que não seja um dígito hexadecimal (0-9, A-F)
hex_value = re.sub(r"[^0-9A-Fa-f]", "", hex_value)

# exibe o valor resultante
print("Valor em hexadecimal formatado: ", hex_value)
