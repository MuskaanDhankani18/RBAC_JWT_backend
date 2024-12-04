- Implemented an authentication system where users can register, log in, and log out securely.
- Implemented authorization based on roles such as Admin, User, and Moderator where each role has specific permissions to access certain resources or endpoints.
- Used secure method JWT for managing sessions and user authentication.
- Implemented Role-Based Access Control (RBAC), where the access to resources is determined based on the user's assigned role.

* TECHNOLOGY USED:
  * Backend: Python, Flask
  * Frontend: HTML, JavaScript
  * Database: MongoDB
  * Authentication: JWT

* TEMPLATES:
  - Register Page: This page registers new user and add it in the MongoDB.
  - Login Page : This page authenticates user by validating email and password against MongoDB. Here, after successful login Flask app creates JWT token which is being used across the application to validate current user.
  - Dashboard Page: After successful login, user lands on dashboard page where user can view the links based on their role as given below:
        # For User Role: 
            * Edit User: User can update their existing details.
            * Add Message: User can post messages and view on the same page.
        # For Admin Role:
            * Manage User: Admin can edit and delete user.
            * Filter: Admin can search any username or email and role by using the search filter functionality. 
        # For Moderator Role:
            * Manage Activities: Moderator can view all logs of login, logout and page navigations of all users but not admin.
            * User Posts: Moderator can view all the messages posts by all the users to review.
  
