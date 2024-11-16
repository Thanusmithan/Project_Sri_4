// // // AdminReviewsPage.js
// // import React, { useState } from 'react';
// // import './Css/Admin_Reviews.css'; // Custom CSS file
// // import Header from './Componets/Admin_Header';
// // import Footer from './Componets/Footer';
// // import Alert from 'react-bootstrap/Alert';
// // import RatingStars from './Componets/RatingStars'; // Importing the RatingStars component
// // import { FaTrash, FaReply, FaThumbsUp } from 'react-icons/fa'; // Icons for delete, respond, and like actions

// // const AdminReviewsPage = () => {
// //   const [reviews, setReviews] = useState([
// //     { id: 1, rating: 5, feedback: 'Great service!', response: '', likes: 0, comments: [] },
// //     { id: 2, rating: 4, feedback: 'Very helpful staff.', response: '', likes: 0, comments: [] },
// //   ]);
// //   const [response, setResponse] = useState('');
// //   const [alert, setAlert] = useState({ show: false, message: '', type: '' });
// //   const [selectedReviewId, setSelectedReviewId] = useState(null);
// //   const [comment, setComment] = useState('');

// //   const handleDeleteReview = (id) => {
// //     setReviews(reviews.filter(review => review.id !== id));
// //     setAlert({ show: true, message: 'Review deleted successfully!', type: 'success' });
// //     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
// //   };

// //   const handleRespond = (id) => {
// //     const updatedReviews = reviews.map(review => 
// //       review.id === id ? { ...review, response } : review
// //     );
// //     setReviews(updatedReviews);
// //     setResponse('');
// //     setAlert({ show: true, message: 'Response submitted successfully!', type: 'success' });
// //     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
// //   };

// //   const handleLikeReview = (id) => {
// //     const updatedReviews = reviews.map(review => 
// //       review.id === id ? { ...review, likes: review.likes + 1 } : review
// //     );
// //     setReviews(updatedReviews);
// //     setAlert({ show: true, message: 'You liked the review!', type: 'success' });
// //     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
// //   };

// //   const handleCommentSubmit = (id) => {
// //     const updatedReviews = reviews.map(review => 
// //       review.id === id ? { ...review, comments: [...review.comments, comment] } : review
// //     );
// //     setReviews(updatedReviews);
// //     setComment('');
// //   };

// //   return (
// //     <>
// //       <Header />
// //       <div className="container my-5">
// //         <h2 className="text-center">Ratings and Reviews</h2>

// //         {/* Alert for submission feedback */}
// //         {alert.show && (
// //           <Alert variant={alert.type} onClose={() => setAlert({ show: false })} dismissible>
// //             <strong>{alert.message}</strong>
// //           </Alert>
// //         )}

// //         <div className="reviews-list mt-4">
// //           <h4>Patient Reviews</h4>
// //           <ul className="list-group">
// //             {reviews.map(review => (
// //               <li key={review.id} className="list-group-item d-flex justify-content-between align-items-start">
// //                 <div className="flex-grow-1">
// //                   <strong>Rating: <RatingStars rating={review.rating} /></strong>
// //                   <p>{review.feedback}</p>
// //                   {review.response && <p className="text-success">Response: {review.response}</p>}

// //                   <div className="d-flex align-items-center mt-2">
// //                     <button 
// //                       className="btn btn-primary me-2" 
// //                       onClick={() => handleLikeReview(review.id)}
// //                     >
// //                       <FaThumbsUp className="me-1" /> Like ({review.likes})
// //                     </button>

// //                     <textarea 
// //                       className="form-control me-2" 
// //                       placeholder="Write your response here..." 
// //                       value={response}
// //                       onChange={(e) => setResponse(e.target.value)}
// //                     />
// //                     <button className="btn btn-success" onClick={() => handleRespond(review.id)}>
// //                       <FaReply className="me-1" /> Respond
// //                     </button>
// //                   </div>

// //                   {/* Comments Section */}
// //                   <div className="mt-3">
// //                     <h5>Comments</h5>
// //                     <ul className="list-group">
// //                       {review.comments.map((comment, index) => (
// //                         <li key={index} className="list-group-item">{comment}</li>
// //                       ))}
// //                     </ul>
// //                     <div className="d-flex align-items-center">
// //                       <textarea 
// //                         className="form-control me-2" 
// //                         placeholder="Add a comment..." 
// //                         value={comment}
// //                         onChange={(e) => setComment(e.target.value)}
// //                       />
// //                       <button className="btn btn-info" onClick={() => handleCommentSubmit(review.id)}>
// //                         Add Comment
// //                       </button>
// //                     </div>
// //                   </div>
// //                 </div>
// //                 <FaTrash className="text-danger" onClick={() => handleDeleteReview(review.id)} />
// //               </li>
// //             ))}
// //           </ul>
// //         </div>
// //       </div>
// //       <Footer />
// //     </>
// //   );
// // };

// // export default AdminReviewsPage;


// // AdminReviewsPage.js
// import React, { useState } from 'react';
// import './Css/Admin_Reviews.css'; // Custom CSS file
// import Header from './Componets/Admin_Header';
// import Footer from './Componets/Footer';
// import Alert from 'react-bootstrap/Alert';
// import RatingStars from './Componets/RatingStars'; // Importing the RatingStars component
// import { FaTrash, FaReply, FaThumbsUp } from 'react-icons/fa'; // Icons for delete, respond, and like actions

// const AdminReviewsPage = () => {
//   const [reviews, setReviews] = useState([
//     { id: 1, rating: 5, feedback: 'Great service!', response: '', likes: 0, comments: [] },
//     { id: 2, rating: 4, feedback: 'Very helpful staff.', response: '', likes: 0, comments: [] },
//   ]);
//   const [alert, setAlert] = useState({ show: false, message: '', type: '' });
//   const [response, setResponse] = useState('');
//   const [comment, setComment] = useState('');
//   const [selectedReviewId, setSelectedReviewId] = useState(null);

//   const handleDeleteReview = (id) => {
//     setReviews(reviews.filter(review => review.id !== id));
//     setAlert({ show: true, message: 'Review deleted successfully!', type: 'success' });
//     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
//   };

//   const handleRespond = (id) => {
//     const updatedReviews = reviews.map(review => 
//       review.id === id ? { ...review, response } : review
//     );
//     setReviews(updatedReviews);
//     setResponse('');
//     setAlert({ show: true, message: 'Response submitted successfully!', type: 'success' });
//     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
//   };

//   const handleLikeReview = (id) => {
//     const updatedReviews = reviews.map(review => 
//       review.id === id ? { ...review, likes: review.likes + 1 } : review
//     );
//     setReviews(updatedReviews);
//     setAlert({ show: true, message: 'You liked the review!', type: 'success' });
//     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
//   };

//   const handleCommentSubmit = (id) => {
//     if (!comment) return; // Prevent submitting empty comments
//     const updatedReviews = reviews.map(review => 
//       review.id === id ? { ...review, comments: [...review.comments, comment] } : review
//     );
//     setReviews(updatedReviews);
//     setComment('');
//   };

//   return (
//     <>
//       <Header />
//       <div className="container my-5">
//         <h2 className="text-center">Ratings and Reviews</h2>

//         {/* Alert for submission feedback */}
//         {alert.show && (
//           <Alert variant={alert.type} onClose={() => setAlert({ show: false })} dismissible>
//             <strong>{alert.message}</strong>
//           </Alert>
//         )}

//         <div className="reviews-list mt-4">
//           <h4>Patient Reviews</h4>
//           <ul className="list-group">
//             {reviews.map(review => (
//               <li key={review.id} className="list-group-item d-flex justify-content-between align-items-start">
//                 <div className="flex-grow-1">
//                   <strong>Rating: <RatingStars rating={review.rating} /></strong>
//                   <p>{review.feedback}</p>
//                   {review.response && <p className="text-success"><strong>Response:</strong> {review.response}</p>}

//                   <div className="d-flex align-items-center mt-2">
//                     <button 
//                       className="btn btn-primary me-2" 
//                       onClick={() => handleLikeReview(review.id)}
//                     >
//                       <FaThumbsUp className="me-1" /> Like ({review.likes})
//                     </button>
//                   </div>
//                 </div>
//                 <button className="btn btn-danger" onClick={() => handleDeleteReview(review.id)}>
//                   <FaTrash />
//                 </button>
//               </li>
//             ))}
//           </ul>
//         </div>
//       </div>
//       <Footer />
//     </>
//   );
// };

// export default AdminReviewsPage;


// AdminReviewsPage.js
import React, { useState } from 'react';
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import './Css/Admin_Reviews.css'; // Custom CSS file
import Alert from 'react-bootstrap/Alert';
import RatingStars from './Componets/RatingStars';
import { FaTrash, FaReply, FaThumbsUp } from 'react-icons/fa';

const AdminReviewsPage = () => {
  const [reviews, setReviews] = useState([
    { id: 1, rating: 5, feedback: 'Great service!', response: '', likes: 0, comments: [] },
    { id: 2, rating: 4, feedback: 'Very helpful staff.', response: '', likes: 0, comments: [] },
  ]);
  const [alert, setAlert] = useState({ show: false, message: '', type: '' });
  const [response, setResponse] = useState('');
  const [comment, setComment] = useState('');

  const handleDeleteReview = (id) => {
    setReviews(reviews.filter(review => review.id !== id));
    setAlert({ show: true, message: 'Review deleted successfully!', type: 'success' });
    setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
  };

  const handleRespond = (id) => {
    const updatedReviews = reviews.map(review =>
      review.id === id ? { ...review, response } : review
    );
    setReviews(updatedReviews);
    setResponse('');
    setAlert({ show: true, message: 'Response submitted successfully!', type: 'success' });
    setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
  };

  const handleLikeReview = (id) => {
    const updatedReviews = reviews.map(review =>
      review.id === id ? { ...review, likes: review.likes + 1 } : review
    );
    setReviews(updatedReviews);
    setAlert({ show: true, message: 'You liked the review!', type: 'success' });
    setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
  };

  const handleCommentSubmit = (id) => {
    if (!comment) return;
    const updatedReviews = reviews.map(review =>
      review.id === id ? { ...review, comments: [...review.comments, comment] } : review
    );
    setReviews(updatedReviews);
    setComment('');
  };

  return (
    <>
      <Header />
      <div className="container my-5 review-container">
        <h2 className="text-center my-3">Ratings and Reviews</h2>

        {/* Alert for submission feedback */}
        {alert.show && (
          <Alert variant={alert.type} onClose={() => setAlert({ show: false })} dismissible className='admin-review-alert'>
            <strong>{alert.message}</strong>
          </Alert>
        )}

        <div className="reviews-list mt-4">
          <h4>Patient Reviews</h4>
          <ul className="list-group">
            {reviews.map(review => (
              <li key={review.id} className="list-group-item d-flex justify-content-between align-items-start">
                <div className="flex-grow-1">
                  <strong>Rating: <RatingStars rating={review.rating} /></strong>
                  <p>{review.feedback}</p>
                  {review.response && <p className="text-success"><strong>Response:</strong> {review.response}</p>}

                  <div className="d-flex align-items-center mt-2">
                    <button
                      className="btn btn-primary me-2"
                      onClick={() => handleLikeReview(review.id)}
                    >
                      <FaThumbsUp className="me-1" /> Like ({review.likes})
                    </button>
                  </div>
                </div>
                <button className="btn btn-danger" onClick={() => handleDeleteReview(review.id)}>
                  <FaTrash />
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <Footer />
    </>
  );
};

export default AdminReviewsPage;
