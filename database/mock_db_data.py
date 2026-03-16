import sqlite3

if __name__ == '__main__':
    connection = sqlite3.connect('CuciSec.db')
    cursor = connection.cursor()

    cursor.execute(
        ''' 
        INSERT INTO Blacklist (ip,reason) VALUES ('127.0.1.1', 'test')
        ''')

    connection.commit()
    connection.close()