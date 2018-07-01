import sys

# https://www.c64-wiki.com/wiki/BASIC_token
# tokens from 0x80 to 0xCB (inclusive)
TOKENS = ['END','FOR','NEXT','DATA','INPUT#','INPUT','DIM','READ','LET','GOTO','RUN','IF','RESTORE','GOSUB','RETURN','REM','STOP','ON','WAIT','LOAD','SAVE','VERIFY','DEF','POKE','PRINT#','PRINT','CONT','LIST','CLR','CMD','SYS','OPEN','CLOSE','GET','NEW','TAB(','TO','FN','SPC(','THEN','NOT','STEP','+','−','*','/','^','AND','OR','>','=','<','SGN','INT','ABS','USR','FRE','POS','SQR','RND','LOG','EXP','COS','SIN','TAN','ATN','PEEK','LEN','STR$','VAL','ASC','CHR$','LEFT$','RIGHT$','MID$','GO']
FIRST_TOKEN = 0x80

def decode_basic_token(token):
    if token == 0:
        return '\n'.encode()

    if token == 0xFF:
        return 'PI '.encode()

    if token < FIRST_TOKEN:
        return bytes([token])

    token_index = token - FIRST_TOKEN
    if token_index >= len(TOKENS):
        raise Exception('Invalid token')

    # return the token, with a space since multiple tokens can appear in a row
    return (TOKENS[token_index] + ' ').encode()

def main(prg_filepath, output_filepath):
    with open(prg_filepath, 'rb') as prg_file:
        tokenized_basic = prg_file.read()

    with open(output_filepath, 'wb') as output_file:
        for token in tokenized_basic:
            output_file.write(decode_basic_token(token))

if __name__ == '__main__':
    main(*sys.argv[1:])
