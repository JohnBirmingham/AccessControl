import random
import re
number_of_attributes = input("Put a number of attrbutes(min 4): ")
attribute_array = []
i = 0
condition_one = 0
condition_two = 0
while i < int(number_of_attributes):
   attribute_array.append(input(f"Attribute {i}: "))
   i+=1
users = []
Valid_User = []
Invaild_User = []
n = int(number_of_attributes)
for user_id in range(1,11):
   num_attrs = random.randint(2, n)
   user_attrs = set(random.sample(attribute_array, num_attrs))
   users.append({'user_id':user_id, 'attributes':user_attrs})
for user in users:
    user_attrs = user['attributes']
    for attribute in user_attrs:
        if attribute == attribute_array[0]:
            condition_one+=1
        elif attribute == attribute_array[1]:
            condition_one+=1
        else:
            condition_two+=1
    if (condition_one >= 2) or (condition_two >= 2):
            Valid_User.append(user['user_id'])
    if (condition_one < 2) and (condition_two < 2):
        Invaild_User.append(user['user_id'])
    condition_two = 0
    condition_one = 0
#print(users)
#print(attribute_array)
print("Valid User List")
for user_id in Valid_User:
    print(f"User {user_id}: TRUE")
for user_id in Invaild_User:
    print(f"user {user_id}: FALSE")
