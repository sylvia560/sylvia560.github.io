import pandas as pd
from dbtestmysql import SessionLocal
from modelsmysql import auth, Doctors, Nurses, Patient, Clinical_services, Billing

def load_data_from_csv():
    session = SessionLocal()
    
    # Step 1: Load and insert data into the 'auth' table
    auth_df = pd.read_csv('authentication.csv')
    for index, row in auth_df.iterrows():
        authentication = auth(
            User_ID=row['User_ID'],
            Username=row['Username'],
            Password=row['Password'],
            National_ID=row['National_ID'],
            Full_Name=row['Full_Name'],
            Email=row['Email'],
            Role=row['Role'],
            Last_Login_Date=row['Last_Login_Date'],
            Activity_Logs=row['Activity_Logs'],
            banned_until=row['banned_until']
        )
        session.add(authentication)
    '''
    # Step 2: Load and insert data into the 'Doctors' table
    doctors_df = pd.read_csv('doctors.csv')
    for index, row in doctors_df.iterrows():
        doctor = Doctors(
            Doctor_ID=row['Doctor_ID'],
            Department_ID=row['Department_ID'],
            Department_Name_x=row['Department_Name_x'],
            Contact=row['Contact'],
            Available_Hours=row['Available_Hours'],
            Department_Name_y=row['Department_Name_y']
        )
        session.add(doctor)
    
    # Step 3: Load and insert data into the 'Nurses' table
    nurses_df = pd.read_csv('nurses.csv')
    for index, row in nurses_df.iterrows():
        nurse = Nurses(
            Nurse_ID=row['Nurse_ID'],
            Department_ID=row['Department_ID'],
            Department_Name_x=row['Department_Name_x'],
            Contact=row['Contact'],
            Shift_Hours=row['Shift_Hours'],
            Department_Name_y=row['Department_Name_y']
        )
        session.add(nurse)
    
    # Step 4: Load and insert data into the 'Patient' table
    patients_df = pd.read_csv('patients.csv')
    for index, row in patients_df.iterrows():
        patient = Patient(
            User_ID=row['User_ID'],
            Patient_ID_Clinical=row['Patient_ID_Clinical'],
            Patient_ID_Billing=row['Patient_ID_Billing'],
            Gender=row['Gender'],
            Contact=row['Contact'],
            Allergies=row['Allergies'],
            Chronic_Conditions=row['Chronic_Conditions'],
            Purpose_of_Visit=row['Purpose_of_Visit'],
            Prescribing_Doctor_ID=row['Prescribing_Doctor_ID']
        )
        session.add(patient)
    
    # Step 5: Load and insert data into the 'Clinical_services' table
    clinical_services_df = pd.read_csv('clinical_services_modified.csv')
    for index, row in clinical_services_df.iterrows():
        clinical_service = Clinical_services(
            Patient_ID=row['Patient_ID'],
            Department_ID=row['Department_ID'],
            Medication_Name=row['Medication_Name'],
            Dosage_Instructions=row['Dosage_Instructions'],
            Responsible_Doctor_ID=row['Responsible_Doctor_ID'],
            Treatment_Details=row['Treatment_Details'],
            Department_Name=row['Department_Name']
        )
        session.add(clinical_service)
    
    # Step 6: Load and insert data into the 'Billing' table
    billing_df = pd.read_csv('billing and finance (4).csv')
    for index, row in billing_df.iterrows():
        billing = Billing(
            Patient_ID=row['Patient_ID'],
            Status=row['Status'],
            Payment_Mode=row['Payment_Mode'],
            Amount_Paid=row['Amount_Paid']
        )
        session.add(billing)
    '''
    # Commit all changes and close the session
    session.commit()
    session.close()

# Call the function to load data
load_data_from_csv()