import sqlite3

if __name__ == '__main__':
    connection = sqlite3.connect('CuciSec.db')
    cursor = connection.cursor()

    cursor.execute(
        '''
        DELETE
        FROM Blacklist;
        ''')

    cursor.execute(
        '''
        DELETE
        FROM Rules;
        '''
    )

    # cursor.execute(
    #     '''
    #     DELETE
    #     FROM Logs;
    #     '''
    # )

    # id reset
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="Blacklist" OR name="Rules";')


    # cursor.execute('''
    #                INSERT INTO Rules (ip_src, port, protocol, action, description, enabled)
    #                VALUES (NULL, NULL, 'ICMP', 'ACCEPT', 'TEST for ICMP', 1)
    #                ''')

    connection.commit()
    connection.close()