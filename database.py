import sqlite3
from datetime import datetime

class database_handler:
    def __init__(self, db_name="mydatabase.db"):
        """
        This module is responsible for manipulating the database.
        """
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                gpt_analysis TEXT,
                vt_info TEXT,
                date DATETIME            
            );
        ''')
        self.connection.commit()

    def insert_data(self, domain:str, gpt_analysis:str, vt_info = None):
        """
        Adds new records to the database.

        If there is already information for a domain and you are asked to enter another one, 
        the function will overwrite the previous record
        """
        try:
            self.cursor.execute('''
                INSERT INTO domains_data (domain, gpt_analysis, vt_info, date)
                VALUES (?, ?, ?, ?)
            ''', (domain, gpt_analysis, f"{vt_info}", datetime.now()))

            self.connection.commit()
        
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: domains_data.domain" in str(e):
                self._del_record(domain)
                self.insert_data(domain, gpt_analysis, vt_info)
            else:
                print("ERROR: The data could not be saved in the database.")

    def show_all(self):
        """
        Return an array with all the information in the bank.
        """
        self.cursor.execute('''
            SELECT * FROM domains_data;
        ''')

        return self.cursor.fetchall()

    def find_record(self, domain:str):
        """
        Returns an array with the record of a domain's information if it exists.
        """
        self.cursor.execute('''
        SELECT * FROM domains_data WHERE domain = ?
        ''', (domain,))

        return self.cursor.fetchall()
    
    def _del_record(self, domain):
        """
        Deletes a record from the database.
        """
        self.cursor.execute('''
        DELETE FROM domains_data WHERE domain = ?
        ''', (domain,))
        self.connection.commit()


    def del_all(self):
        """
        Deletes all information from the database.
        """
        self.cursor.execute('''
        DELETE FROM domains_data
        ''')
        self.connection.commit()

    def close(self):
        """
        Terminates operations with the database.
        """
        self.connection.commit()
        self.connection.close()
