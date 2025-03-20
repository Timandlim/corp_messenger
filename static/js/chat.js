document.addEventListener('DOMContentLoaded', () => {
    var socket = io();
  
    socket.on('new_message', function(data) {
      let chatHistory = document.getElementById('chat-history');
      let card = document.createElement('div');
      card.className = 'card mb-2';
      let cardBody = document.createElement('div');
      cardBody.className = 'card-body';
      let title = document.createElement('h6');
      title.className = 'card-title';
      title.textContent = data.sender;
      let text = document.createElement('p');
      text.className = 'card-text';
      text.textContent = data.content;
      let timestamp = document.createElement('p');
      timestamp.className = 'card-text';
      timestamp.innerHTML = '<small class="text-muted">' + data.timestamp + '</small>';
      cardBody.appendChild(title);
      cardBody.appendChild(text);
      cardBody.appendChild(timestamp);
      card.appendChild(cardBody);
      chatHistory.appendChild(card);
      chatHistory.scrollTop = chatHistory.scrollHeight;
    });
  
    document.getElementById('message-form').addEventListener('submit', function(e) {
      e.preventDefault();
      let group_id = document.getElementById('group_id').value;
      let message = document.getElementById('message').value;
      if (!group_id || !message) return;
      socket.emit('send_message', { group_id: group_id, message: message });
      document.getElementById('message').value = '';
    });
  });
  