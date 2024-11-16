import React, { useState, useEffect } from 'react'; // Import useEffect
import './Css/Patient_Message.css';
// import Header from './Componets/Patient_Header';
import Header from './Componets/Patientdashboard_Header';
import Footer from './Componets/Footer';
import Alert from 'react-bootstrap/Alert';
import { FaPaperPlane, FaInbox, FaEdit, FaTrash, FaBullhorn } from "react-icons/fa";

const PatientMessagingPage = () => {
  const [sentMessages, setSentMessages] = useState([]);
  const [receivedMessages, setReceivedMessages] = useState([
    { id: 1, sender: "Admin", content: "Please arrive 15 minutes early for your appointment." }
  ]);
  const [announcements, setAnnouncements] = useState([
    { id: 101, content: "Clinic closed on public holidays." }
  ]);
  const [recipient, setRecipient] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [editingMessage, setEditingMessage] = useState(null);
  const [alert, setAlert] = useState({ show: false, message: '', type: '' });

  // Auto dismiss alert after 2 seconds
  useEffect(() => {
    if (alert.show) {
      const timer = setTimeout(() => {
        handleCloseAlert();
      }, 2000); // 2000 milliseconds = 2 seconds

      return () => clearTimeout(timer); // Clear timeout if the component unmounts
    }
  }, [alert.show]);

  // Handle sending or updating a message
  const handleSendMessage = () => {
    // Check if recipient or message content is empty
    if (!recipient || !messageContent) {
      setAlert({ show: true, message: 'Please enter both a recipient and a message.', type: 'danger' });
      return;
    }

    if (editingMessage) {
      const updatedMessages = sentMessages.map(msg =>
        msg.id === editingMessage.id ? { ...msg, content: messageContent } : msg
      );
      setSentMessages(updatedMessages);
      setEditingMessage(null);
    } else {
      const newMessage = { id: Date.now(), recipient, content: messageContent };
      setSentMessages([...sentMessages, newMessage]);
    }

    setRecipient('');
    setMessageContent('');
    setAlert({ show: true, message: 'Message sent successfully!', type: 'success' });
  };

  // Handle editing an existing message
  const handleEditMessage = (message) => {
    setEditingMessage(message);
    setRecipient(message.recipient);
    setMessageContent(message.content);
  };

  // Handle deleting a message (either sent or received)
  const handleDeleteMessage = (id, isSent) => {
    if (isSent) {
      setSentMessages(sentMessages.filter(msg => msg.id !== id));
    } else {
      setReceivedMessages(receivedMessages.filter(msg => msg.id !== id));
    }
  };

  // Handle alert close
  const handleCloseAlert = () => {
    setAlert({ show: false, message: '', type: '' });
  };

  return (
    <>
      <Header />
      <div className="container my-5 ">
        <h2 className="text-center-center">Send a Message</h2>

        {/* Alert for empty inputs */}
        {/* {alert.show && (
          <Alert
            variant={alert.type}
            onClose={handleCloseAlert}
            dismissible
            style={{ maxWidth: '500px', padding: '15px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            className='patient-service-alert'
          ><i class="bi bi-x-circle-fill"></i>
            <strong>{alert.message}</strong>
          </Alert>
        )} */}
        {/* Alert for empty inputs */}
        {alert.show && (
          <Alert
            variant={alert.type}
            onClose={handleCloseAlert}
            dismissible
            className="patient-message-alert d-flex justify-content-between align-items-center p-3"
            style={{ maxWidth: '500px' }}
          >
            <i className="bi bi-x-circle-fill me-2"></i>
            <strong className="flex-grow-1">{alert.message}</strong>
          </Alert>
        )}

        {/* Messaging section */}
        <div className="messaging-section p-4 rounded shadow">
          <h4><FaPaperPlane className="me-2" />{editingMessage ? "Edit Message" : "Message the Admin"}</h4>
          <input
            type="text"
            className="form-control mt-3"
            placeholder="Enter Admin's name or Admin ID"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
          />
          <textarea
            className="form-control mt-3"
            value={messageContent}
            onChange={(e) => setMessageContent(e.target.value)}
            placeholder="Enter message here..."
          ></textarea>
          <button className="btn btn-success mt-3" onClick={handleSendMessage}>
            <FaPaperPlane className="me-2" /> {editingMessage ? "Update Message" : "Send Message"}
          </button>
        </div>

        {/* Sent Messages section */}
        <div className="messages-display mt-5 p-4 rounded shadow">
          <h4><FaInbox className="me-2" />Sent Messages</h4>
          <ul className="list-group">
            {sentMessages.map((msg) => (
              <li key={msg.id} className="list-group-item d-flex justify-content-between align-items-center">
                <span>To: {msg.recipient} - {msg.content}</span>
                <div>
                  <FaEdit className="text-primary me-2" onClick={() => handleEditMessage(msg)} />
                  <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, true)} />
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Received Messages section */}
        <div className="messages-display mt-5 p-4 rounded shadow">
          <h4><FaInbox className="me-2" />Received Messages from Admin</h4>
          <ul className="list-group">
            {receivedMessages.map((msg) => (
              <li key={msg.id} className="list-group-item d-flex justify-content-between align-items-center">
                <span>From: {msg.sender} - {msg.content}</span>
                <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, false)} />
              </li>
            ))}
          </ul>
        </div>

        {/* Announcements section */}
        <div className="announcements-section mt-5 p-4 rounded shadow">
          <h4><FaBullhorn className="me-2" />Admin Announcements</h4>
          <ul className="list-group">
            {announcements.map((announcement) => (
              <li key={announcement.id} className="list-group-item">
                {announcement.content}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <Footer />
    </>
  );
};

export default PatientMessagingPage;