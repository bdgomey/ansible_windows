import csv
from faker import Faker 

fake = Faker() 

# Define the number of rows to generate
num_rows = 10

# Define the column headers
headers = ["name", "firstname", "surname", "company", "password", "state", "groups", "street", "city", "state_province", "postal_code", "country", "telephone_number"]

# Open the CSV file in write mode
with open('users.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    groups = ["Employees", "IT", "Engineers", "Developers", "Security", "Sales", "Marketing", "Finance"]
    acl = ['GenericAll','GenericWrite','WriteOwner','WriteDACL','AllExtendedRights','ForceChangePassword','Self','WriteProperty']
    # Write the headers to the CSV file
    writer.writeheader()

    # Generate and write the rows
    for _ in range(num_rows):
        writer.writerow({
            "name": fake.name(),
            "firstname": fake.first_name(),
            "surname": fake.last_name(),
            "company": fake.company(),
            "password": fake.bothify("##?#??##"),
            "groups": fake.random_element(elements=groups),
            "street": fake.street_address(),
            "city": fake.city(),
            "state": fake.state(),
            "postal_code": fake.bothify("#####"),
            "country": fake.bothify("??"),
            "telephone_number": fake.bothify("###-###-####"),
        })