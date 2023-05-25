.686
.model flat, stdcall
option casemap: none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\msvcrt.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\msvcrt.lib
includelib \masm32\lib\masm32.lib

.data
    bufferSize equ 512
    buffer db bufferSize dup(0)
    file_input db 512 dup(0)

    input_prompt db "Digite o nome do arquivo de entrada: ", 0
    output_prompt db "Digite o nome do arquivo de saida(encriptado): ", 0
    decrypt_prompt db "Digite o nome do arquivo para descriptar: ", 0
    key_prompt db "Digite a chave entre 1 e 20: ", 0
    menuPrompt db "Escolha uma opcao:", 0
    encryptOption db "1 - Criptografar", 0
    decryptOption db "2 - Descriptografar", 0
    criptAnalisis db "3 - Criptoanalise", 0
    exitOption db "4 - Sair", 0
    chooseOption db "Escolha uma opcao: ", 0
    invalidOptionMessage db "Opcao invalida! Tente novamente.", 0
    successMessage db "Operacao concluida com sucesso!", 0
    newline db 13, 10, 0 

.data?

    input_filename db 256 dup(?)
    decrypt_filename db 256 dup(?)
    outputFile db 256 dup(?)
    input_key db 50 dup(?)

    bytesRead dd ?
    bytesWritten dd ?
    
    handleI dd ?
    handleO dd ?
    
    console_count dd ?
    filebytesread dd ?

    inputHandle dd ?
    outputHandle dd ?


.code

EncryptFunction:

    push ebp
    mov ebp, esp

    ; Acessar os parâmetros através do registrador EBP e deslocamentos na pilha
    mov ebx, [ebp+16]   ; Valor da chave

    xor edi, edi
    ;Criptografar o conteudo do buffer
    mov esi, [ebp+8] ; carregar o endereco do buffer em esi ; buffer de entrada
    EncryptLoop:
        mov al, [esi]
        add al, bl
        mov [esi], al
        inc esi
        inc edi
        cmp edi, [ebp+12] ; tamanho do buffer de entrada
        jl EncryptLoop

    mov esp, ebp
    pop ebp
    ret 12

DecryptFunction:

    push ebp
    mov ebp, esp

    ; Acessar os parâmetros através do registrador EBP e deslocamentos na pilha
    mov ebx, [ebp+16]   ; Valor da chave

    xor edi, edi
    ;Descriptografar o conteudo do buffer
    mov esi, [ebp+8] ; carregar o endereco do buffer em esi ; buffer de entrada
    DecryptLoop:
        mov al, [esi]
        sub al, bl
        mov [esi], al
        inc esi
        inc edi
        cmp edi, [ebp+12] ; tamanho do buffer de entrada
        jl DecryptLoop

    mov esp, ebp
    pop ebp
    ret 12


start:
    invoke GetStdHandle, STD_INPUT_HANDLE 
    mov inputHandle, eax

    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov outputHandle, eax ; salvar o handle de saída em ebx

    invoke WriteConsole, outputHandle, OFFSET menuPrompt, LENGTHOF menuPrompt, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha

    invoke WriteConsole, outputHandle, OFFSET encryptOption, LENGTHOF encryptOption, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha

    invoke WriteConsole, outputHandle, OFFSET decryptOption, LENGTHOF decryptOption, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha

    invoke WriteConsole, outputHandle, OFFSET criptAnalisis, LENGTHOF criptAnalisis, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL

    invoke WriteConsole, outputHandle, OFFSET exitOption, LENGTHOF exitOption, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha

    invoke WriteConsole, outputHandle, OFFSET chooseOption, LENGTHOF chooseOption, NULL, NULL

    invoke ReadConsole, inputHandle, addr buffer, bufferSize, addr bytesRead, NULL
    mov eax, bytesRead

    ; Verificar a opcao escolhida
    cmp byte ptr [buffer], '1'
    je EncryptOption
    cmp byte ptr [buffer], '2'
    je DecryptOption
    cmp byte ptr [buffer], '3'
    je CriptAnalisis
    cmp byte ptr [buffer], '4'
    je ExitOption
    jmp InvalidOption

EncryptOption:

    ; Obter o nome do arquivo de entrada
    invoke WriteConsole, outputHandle, OFFSET input_prompt, LENGTHOF input_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET input_filename, LENGTHOF input_filename, addr console_count, NULL

    mov esi, offset input_filename
    tirar_:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_
    dec esi
    xor al, al
    mov [esi], al

    ; Abrir o arquivo de entrada
    invoke CreateFile, addr input_filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov handleI, eax ; salvar o handle do arquivo de entrada em ecx

    ; Verificar se o arquivo de entrada foi aberto com sucesso
    cmp handleI, INVALID_HANDLE_VALUE
    je EncryptFileError 

    invoke WriteConsole, outputHandle, OFFSET output_prompt, LENGTHOF output_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET outputFile, LENGTHOF outputFile, addr console_count, NULL

    mov esi, OFFSET outputFile
    tirar_enc:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_enc
    dec esi
    xor al, al
    mov [esi], al

    ; Criar o arquivo de saida
    invoke CreateFile, addr outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov handleO, eax 

    ; Verificar se o arquivo de saida foi criado com sucesso
    cmp handleO, INVALID_HANDLE_VALUE
    je EncryptFileError

    invoke WriteConsole, outputHandle, OFFSET key_prompt, LENGTHOF key_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET input_key, LENGTHOF input_key, addr console_count, NULL
    
    mov esi, OFFSET input_key
    tirar_key:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_key
    dec esi
    xor al, al
    mov [esi], al

    invoke atodw, addr input_key
    mov ebx, eax

    ; Ler o conteudo do arquivo de entrada e criptografar

    EncryptFileLoop:

    invoke ReadFile, handleI, OFFSET file_input, 512, OFFSET filebytesread, NULL

    push ebx
    push filebytesread
    push OFFSET file_input
    call EncryptFunction
    
    invoke WriteFile, handleO, OFFSET file_input, filebytesread, OFFSET bytesWritten, NULL
    cmp filebytesread, 0
    jne EncryptFileLoop
    
    invoke CloseHandle, handleI
    invoke CloseHandle, handleO

    jmp Success

EncryptFileError:
    ; Exibir mensagem de erro
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL
    invoke WriteConsole, outputHandle, OFFSET invalidOptionMessage, LENGTHOF invalidOptionMessage, NULL, NULL

    jmp start

DecryptOption:
    ; Obter o nome do arquivo de entrada
    invoke WriteConsole, outputHandle, OFFSET input_prompt, LENGTHOF input_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET input_filename, LENGTHOF input_filename, addr console_count, NULL

    mov esi, OFFSET input_filename
    tirar_dec:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_dec
    dec esi
    xor al, al
    mov [esi], al

    ; Abrir o arquivo de entrada
    invoke CreateFile, OFFSET input_filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov handleI, eax ; salvar o handle do arquivo de entrada em ecx

    ; Verificar se o arquivo de entrada foi aberto com sucesso
    cmp handleI, INVALID_HANDLE_VALUE
    je DecryptFileError
    
    invoke WriteConsole, outputHandle, OFFSET decrypt_prompt, LENGTHOF decrypt_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET decrypt_filename, LENGTHOF decrypt_filename, addr console_count, NULL

    mov esi, OFFSET decrypt_filename
    tirar_decry:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_decry
    dec esi
    xor al, al
    mov [esi], al

    ; Criar o arquivo de saida
    invoke CreateFile, OFFSET decrypt_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov handleO, eax ; salvar o handle do arquivo de saida em ebx

    ; Verificar se o arquivo de saida foi criado com sucesso
    cmp handleO, INVALID_HANDLE_VALUE
    je DecryptFileError

    invoke WriteConsole, outputHandle, OFFSET key_prompt, LENGTHOF key_prompt, NULL, NULL
    invoke ReadConsole, inputHandle, OFFSET input_key, LENGTHOF input_key, addr console_count, NULL
    
    mov esi, OFFSET input_key
    tirar_key_:
    mov al, [esi]
    inc esi
    cmp al, 13
    jne tirar_key_
    dec esi
    xor al, al
    mov [esi], al

    invoke atodw, addr input_key
    mov ebx, eax
    ; Ler o conteudo do arquivo de entrada e criptografar

    DecryptFileLoop:

    invoke ReadFile, handleI, OFFSET file_input, 512, OFFSET filebytesread, NULL

    ;chamada da funcao
    push ebx
    push filebytesread
    push OFFSET file_input
    call DecryptFunction
    
    invoke WriteFile, handleO, OFFSET file_input, filebytesread, OFFSET bytesWritten, NULL
    cmp filebytesread, 0
    jne DecryptFileLoop
    
    invoke CloseHandle, handleI
    invoke CloseHandle, handleO

    jmp Success

DecryptFileError:
    ; Exibir mensagem de erro
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha
    invoke WriteConsole, outputHandle, OFFSET invalidOptionMessage, LENGTHOF invalidOptionMessage, NULL, NULL
    jmp start

CriptAnalisis:
    ; CriptoAnalise
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha
    jmp Success

InvalidOption:
    ; Mensagem de opcaoo invalida
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha
    invoke WriteConsole, outputHandle, OFFSET invalidOptionMessage, LENGTHOF invalidOptionMessage, NULL, NULL

    jmp start

Success:
    ; Exibir mensagem de sucesso
    invoke WriteConsole, outputHandle, OFFSET newline, LENGTHOF newline, NULL, NULL ; Nova linha
    invoke WriteConsole, outputHandle, OFFSET successMessage, LENGTHOF successMessage, NULL, NULL

    jmp start

ExitOption:
    ; Sair do programa
    invoke ExitProcess, 0

end start