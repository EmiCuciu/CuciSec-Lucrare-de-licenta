import sqlite3

if __name__ == '__main__':
    connection = sqlite3.connect('CuciSec.db')
    cursor = connection.cursor()

    # cursor.execute(
    #     '''
    #     INSERT INTO Blacklist (ip, reason)
    #     VALUES ('10.0.2.15', 'test')
    #     ''')
    #
    cursor.execute(
        '''
        DELETE
        FROM Blacklist;
        ''')

    connection.commit()
    connection.close()