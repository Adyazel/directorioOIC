function loadUserData(userId) {
    fetch(`/get_user/${userId}`)
      .then(response => response.json())
      .then(user => {
        document.getElementById('userId').value = user.id;
        document.getElementById('username').value = user.username;
        document.getElementById('email').value = user.email;
        // No establezcas la contraseña
        $('#editUserModal').modal('show');
      });
  }
  
  document.getElementById('editUserForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const userId = document.getElementById('userId').value;
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    const userData = { id: userId, username: username, email: email, password: password };
  
    fetch('/update_user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    })
    .then(response => response.json())
    .then(data => {
      alert(data.message);
      $('#editUserModal').modal('hide');
      // Aquí debes recargar la parte de la tabla donde se muestran los usuarios o la página completa
    })
    .catch(error => {
      console.error('Error:', error);
    });
  });
  