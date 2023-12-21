import csv
from faker import Faker 

fake = Faker() 

# Define the number of rows to generate
num_rows = 100

# Define the column headers
headers = ["name", "firstname", "surname", "company", "password", "state", "groups", "street", "city", "state_province", "postal_code", "country", "telephone_number"]

# Open the CSV file in write mode
with open('users.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)

    # Write the headers to the CSV file
    writer.writeheader()

    # Generate and write the rows
    for _ in range(num_rows):
        writer.writerow({
            "name": fake.name(),
            "firstname": fake.first_name(),
            "surname": fake.last_name(),
            "company": fake.company(),
            "password": fake.password(),
            "state": fake.state(),
            "groups": "Domain Admins",
            "street": fake.street_address(),
            "city": fake.city(),
            "state_province": fake.state(),
            "postal_code": fake.zipcode(),
            "country": fake.country(),
            "telephone_number": fake.phone_number(),
        })