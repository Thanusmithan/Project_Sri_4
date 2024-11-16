// import React, { useState, useEffect } from 'react';
// import './Css/Message.css';
// import Header from './Componets/Admin_Header';
// import Footer from './Componets/Footer';
// import { FaBullhorn, FaPaperPlane, FaInbox, FaEdit, FaTrash } from "react-icons/fa";
// import Alert from 'react-bootstrap/Alert'; // Import Alert from react-bootstrap

// const AdminMessagingPage = () => {
//   const [announcement, setAnnouncement] = useState('');
//   const [sentMessages, setSentMessages] = useState([]);
//   const [receivedMessages, setReceivedMessages] = useState([
//     { id: 1, sender: "Patient123", content: "Can I schedule an appointment?" }
//   ]);
//   const [recipient, setRecipient] = useState('');
//   const [messageContent, setMessageContent] = useState('');
//   const [editingMessage, setEditingMessage] = useState(null);
//   const [alert, setAlert] = useState({ show: false, message: '', type: '' }); // Alert state

//   // Auto dismiss alert after 2 seconds
//   useEffect(() => {
//     if (alert.show) {
//       const timer = setTimeout(() => {
//         handleCloseAlert();
//       }, 2000); // 2000 milliseconds = 2 seconds

//       return () => clearTimeout(timer); // Clear timeout if the component unmounts
//     }
//   }, [alert.show]);

//   const handlePostAnnouncement = () => {
//     if (!announcement) {
//       setAlert({ show: true, message: 'Please enter an announcement.', type: 'danger' });
//       return;
//     }
    
//     alert("Announcement posted!"); // You can keep or remove this alert as needed.
//     setAnnouncement('');
//     setAlert({ show: true, message: 'Announcement posted successfully!', type: 'success' });
//   };

//   const handleSendMessage = () => {
//     if (!recipient || !messageContent) {
//       setAlert({ show: true, message: 'Please enter both a recipient and a message.', type: 'danger' });
//       return;
//     }

//     if (editingMessage) {
//       const updatedMessages = sentMessages.map(msg =>
//         msg.id === editingMessage.id ? { ...msg, content: messageContent } : msg
//       );
//       setSentMessages(updatedMessages);
//       setEditingMessage(null);
//       setAlert({ show: true, message: 'Message updated successfully!', type: 'success' });
//     } else {
//       const newMessage = { id: Date.now(), recipient, content: messageContent };
//       setSentMessages([...sentMessages, newMessage]);
//       setAlert({ show: true, message: 'Message sent successfully!', type: 'success' });
//     }

//     setRecipient('');
//     setMessageContent('');
//   };

//   const handleEditMessage = (message) => {
//     setEditingMessage(message);
//     setRecipient(message.recipient);
//     setMessageContent(message.content);
//   };

//   const handleDeleteMessage = (id, isSent) => {
//     if (isSent) {
//       setSentMessages(sentMessages.filter(msg => msg.id !== id));
//     } else {
//       setReceivedMessages(receivedMessages.filter(msg => msg.id !== id));
//     }
//   };

//   const handleCloseAlert = () => {
//     setAlert({ show: false, message: '', type: '' });
//   };

//   return (
//     <>
//       <Header />
//       <div className="container my-5 admin-message-container">
//         <h2 className="text-center my-3">Admin Messaging & Announcements</h2>

//         {/* Alert for actions */}
//         {alert.show && (
//           <Alert
//             variant={alert.type}
//             onClose={handleCloseAlert}
//             dismissible
//             style={{ maxWidth: '500px', padding: '15px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
//             className='ser_alert'
//           >
//             <strong>{alert.message}</strong>
//           </Alert>
//         )}

//         <div className="announcement-section mt-4 p-4 rounded shadow">
//           <h4><FaBullhorn className="me-2" />Post Announcement</h4>
//           <textarea
//             className="form-control mt-3"
//             value={announcement}
//             onChange={(e) => setAnnouncement(e.target.value)}
//             placeholder="Enter announcement here..."
//           ></textarea>
//           <button className="btn btn-primary mt-3" onClick={handlePostAnnouncement}>Post Announcement</button>
//         </div>

//         <div className="messaging-section mt-5 p-4 rounded shadow">
//           <h4><FaPaperPlane className="me-2" />{editingMessage ? "Edit Message" : "Message Patients"}</h4>
//           <input
//             type="text"
//             className="form-control mt-3"
//             placeholder="Enter patient's username"
//             value={recipient}
//             onChange={(e) => setRecipient(e.target.value)}
//           />
//           <textarea
//             className="form-control mt-3"
//             value={messageContent}
//             onChange={(e) => setMessageContent(e.target.value)}
//             placeholder="Enter message here..."
//           ></textarea>
//           <button className="btn btn-success mt-3" onClick={handleSendMessage}>
//             <FaPaperPlane className="me-2" /> {editingMessage ? "Update Message" : "Send Message"}
//           </button>
//         </div>

//         <div className="messages-display mt-5 p-4 rounded shadow">
//           <h4><FaInbox className="me-2" />Sent Messages</h4>
//           <ul className="list-group">
//             {sentMessages.map((msg) => (
//               <li key={msg.id} className="message-list-group-item d-flex justify-content-between align-items-center">
//                 <span>To: {msg.recipient} - {msg.content}</span>
//                 <div>
//                   <FaEdit className="text-primary me-2" onClick={() => handleEditMessage(msg)} />
//                   <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, true)} />
//                 </div>
//               </li>
//             ))}
//           </ul>
//         </div>

//         <div className="messages-display mt-5 p-4 rounded shadow">
//           <h4><FaInbox className="me-2" />Received Messages from Patients</h4>
//           <ul className="list-group">
//             {receivedMessages.map((msg) => (
//               <li key={msg.id} className="message-list-group-item d-flex justify-content-between align-items-center">
//                 <span>From: {msg.sender} - {msg.content}</span>
//                 <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, false)} />
//               </li>
//             ))}
//           </ul>
//         </div>
//       </div>
//       <Footer />
//     </>
//   );
// };

// export default AdminMessagingPage;


import React, { useState, useEffect } from 'react';
import './Css/Message.css';
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import { FaBullhorn, FaPaperPlane, FaInbox, FaEdit, FaTrash } from "react-icons/fa";
import Alert from 'react-bootstrap/Alert'; // Import Alert from react-bootstrap

const AdminMessagingPage = () => {
  const [announcement, setAnnouncement] = useState('');
  const [sentMessages, setSentMessages] = useState([]);
  const [receivedMessages, setReceivedMessages] = useState([
    { id: 1, sender: "Patient123", content: "Can I schedule an appointment?" }
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
      }, 2000);

      return () => clearTimeout(timer); // Clear timeout if the component unmounts
    }
  }, [alert.show]);

  const handlePostAnnouncement = () => {
    if (!announcement) {
      setAlert({ show: true, message: 'Please enter an announcement.', type: 'danger' });
      return;
    }
    
    setAnnouncement('');
    setAlert({ show: true, message: 'Announcement posted successfully!', type: 'success' });
  };

  const handleSendMessage = () => {
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
      setAlert({ show: true, message: 'Message updated successfully!', type: 'success' });
    } else {
      const newMessage = { id: Date.now(), recipient, content: messageContent };
      setSentMessages([...sentMessages, newMessage]);
      setAlert({ show: true, message: 'Message sent successfully!', type: 'success' });
    }

    setRecipient('');
    setMessageContent('');
  };

  const handleEditMessage = (message) => {
    setEditingMessage(message);
    setRecipient(message.recipient);
    setMessageContent(message.content);
  };

  const handleDeleteMessage = (id, isSent) => {
    if (isSent) {
      setSentMessages(sentMessages.filter(msg => msg.id !== id));
    } else {
      setReceivedMessages(receivedMessages.filter(msg => msg.id !== id));
    }
  };

  const handleCloseAlert = () => {
    setAlert({ show: false, message: '', type: '' });
  };

  return (
    <>
      <Header />
      <div className="container my-5 admin-message-container">
        <h2 className="text-center my-3">Admin Messaging & Announcements</h2>

        {/* Alert for actions */}
        {alert.show && (
          <Alert
            variant={alert.type}
            onClose={handleCloseAlert}
            dismissible
            className='admin-message-alert'
          >
            <strong>{alert.message}</strong>
          </Alert>
        )}

        <div className="announcement-section mt-4 p-4 rounded shadow">
          <h4><FaBullhorn className="me-2" />Post Announcement</h4>
          <textarea
            className="form-control mt-3"
            value={announcement}
            onChange={(e) => setAnnouncement(e.target.value)}
            placeholder="Enter announcement here..."
          ></textarea>
          <button className="btn btn-primary mt-3" onClick={handlePostAnnouncement}>Post Announcement</button>
        </div>

        <div className="messaging-section mt-5 p-4 rounded shadow">
          <h4><FaPaperPlane className="me-2" />{editingMessage ? "Edit Message" : "Message Patients"}</h4>
          <input
            type="text"
            className="form-control mt-3"
            placeholder="Enter patient's username"
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

        <div className="messages-display mt-5 p-4 rounded shadow">
          <h4><FaInbox className="me-2" />Sent Messages</h4>
          <ul className="list-group">
            {sentMessages.map((msg) => (
              <li key={msg.id} className="message-list-group-item d-flex justify-content-between align-items-center">
                <span>To: {msg.recipient} - {msg.content}</span>
                <div>
                  <FaEdit className="text-primary me-2" onClick={() => handleEditMessage(msg)} />
                  <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, true)} />
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="messages-display mt-5 p-4 rounded shadow">
          <h4><FaInbox className="me-2" />Received Messages from Patients</h4>
          <ul className="list-group">
            {receivedMessages.map((msg) => (
              <li key={msg.id} className="message-list-group-item d-flex justify-content-between align-items-center">
                <span>From: {msg.sender} - {msg.content}</span>
                <FaTrash className="text-danger" onClick={() => handleDeleteMessage(msg.id, false)} />
              </li>
            ))}
          </ul>
        </div>
      </div>
      <Footer />
    </>
  );
};

export default AdminMessagingPage;
