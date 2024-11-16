// // PatientReviewsPage.js
// import React, { useState } from 'react';
// import './Css/Patient_Reviews.css'; // Custom CSS file
// import Header from './Componets/Patient_Header';
// import Footer from './Componets/Footer';
// import Alert from 'react-bootstrap/Alert';
// import RatingStars from './Componets/RatingStars'; // Importing the RatingStars component
// import { FaStar } from 'react-icons/fa'; // For star icon in the header

// const PatientReviewsPage = () => {
//   const [rating, setRating] = useState(0);
//   const [feedback, setFeedback] = useState('');
//   const [reviews, setReviews] = useState([]);
//   const [alert, setAlert] = useState({ show: false, message: '', type: '' });

//   const handleSubmitReview = () => {
//     if (!rating || !feedback) {
//       setAlert({ show: true, message: 'Please provide a rating and feedback.', type: 'danger' });
//       return;
//     }

//     const newReview = { id: Date.now(), rating, feedback };
//     setReviews([...reviews, newReview]);
//     setRating(0);
//     setFeedback('');
//     setAlert({ show: true, message: 'Review submitted successfully!', type: 'success' });

//     setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000); // Hide alert after 2 seconds
//   };

//   return (
//     <>
//       <Header />
//       <div className="container my-5">
//         <h2 className="text-center mb-4">Patient Reviews</h2>

//         {/* Alert for submission feedback */}
//         {alert.show && (
//           <Alert variant={alert.type} onClose={() => setAlert({ show: false })} dismissible>
//             <strong>{alert.message}</strong>
//           </Alert>
//         )}

//         <div className="review-form shadow p-4 mb-5 bg-light rounded">
//           <h4 className="mb-3"> Submit Your Review</h4>
//           <div className="mb-3">
//             <label className="form-label">Rating:</label>
//             <select className="form-select" value={rating} onChange={(e) => setRating(Number(e.target.value))}>
//               <option value="0">Select Rating</option>
//               {[1, 2, 3, 4, 5].map((star) => (
//                 <option key={star} value={star}>{star} Star{star > 1 ? 's' : ''}</option>
//               ))}
//             </select>
//           </div>
//           <div className="mb-3">
//             <label className="form-label">Review:</label>
//             <textarea className="form-control" value={feedback} onChange={(e) => setFeedback(e.target.value)} placeholder="Write your feedback here..." rows="4"></textarea>
//           </div>
//           <button className="btn btn-primary" onClick={handleSubmitReview}>Submit Review</button>
//         </div>

//         {/* Display submitted reviews */}
//         <div className="reviews-list">
//           <h4 className="mb-3">Submitted Reviews</h4>
//           <ul className="list-group">
//             {reviews.map(review => (
//               <li key={review.id} className="list-group-item">
//                 <div className="d-flex justify-content-between align-items-start">
//                   <div>
//                     <strong>Rating: <RatingStars rating={review.rating} /></strong>
//                     <p className="mb-0">{review.feedback}</p>
//                   </div>
//                 </div>
//               </li>
//             ))}
//           </ul>
//         </div>
//       </div>
//       <Footer />
//     </>
//   );
// };

// export default PatientReviewsPage;


// PatientReviewsPage.js
import React, { useState } from 'react';
import './Css/Patient_Reviews.css';
// import Header from './Componets/Patient_Header';
import Header from './Componets/Patientdashboard_Header';
import Footer from './Componets/Footer';
import Alert from 'react-bootstrap/Alert';
import RatingStars from './Componets/RatingStars';

const PatientReviewsPage = () => {
  const [rating, setRating] = useState(0);
  const [feedback, setFeedback] = useState('');
  const [reviews, setReviews] = useState([]);
  const [alert, setAlert] = useState({ show: false, message: '', type: '' });

  const handleSubmitReview = () => {
    if (!rating || !feedback) {
      setAlert({ show: true, message: 'Please provide a rating and feedback.', type: 'danger' });
      return;
    }

    const newReview = { id: Date.now(), rating, feedback, likes: 0 }; // Added likes here
    setReviews([...reviews, newReview]);
    setRating(0);
    setFeedback('');
    setAlert({ show: true, message: 'Review submitted successfully!', type: 'success' });

    setTimeout(() => setAlert({ show: false, message: '', type: '' }), 2000);
  };

  const handleLikeReview = (id) => {
    const updatedReviews = reviews.map(review =>
      review.id === id ? { ...review, likes: review.likes + 1 } : review
    );
    setReviews(updatedReviews);
  };

  return (
    <>
      <Header />
      <div className="container my-5">
        <h2 className="text-center mb-4">Send Ratings and Reviews</h2>
        {/* 
        {alert.show && (
          <Alert variant={alert.type} onClose={() => setAlert({ show: false })} dismissible className="Patient-Review-Alert mb-4">
            <strong>{alert.message}</strong>
          </Alert>
        )} */}
        {alert.show && (
          <Alert
            variant={alert.type}
            onClose={() => setAlert({ show: false })}
            dismissible
            className="Patient-Review-Alert mb-4"
          >
            <strong>{alert.message}</strong>
          </Alert>
        )}
        <div className="review-form shadow p-4 mb-5 bg-light rounded">
          <h4 className="mb-3">Submit Your Review</h4>
          <div className="mb-3">
            <label className="form-label">Rating:</label>
            <select className="form-select" value={rating} onChange={(e) => setRating(Number(e.target.value))}>
              <option value="0">Select Rating</option>
              {[1, 2, 3, 4, 5].map((star) => (
                <option key={star} value={star}>{star} Star{star > 1 ? 's' : ''}</option>
              ))}
            </select>
          </div>
          <div className="mb-3">
            <label className="form-label">Review:</label>
            <textarea className="form-control" value={feedback} onChange={(e) => setFeedback(e.target.value)} placeholder="Write your feedback here..." rows="4"></textarea>
          </div>
          <button className="btn btn-primary" onClick={handleSubmitReview}>Submit Review</button>
        </div>

        <div className="reviews-list">
          <h4 className="mb-3">Submitted Reviews</h4>
          <ul className="list-group">
            {reviews.map(review => (
              <li key={review.id} className="list-group-item">
                <div className="d-flex justify-content-between align-items-start">
                  <div>
                    <strong>Rating: <RatingStars rating={review.rating} /></strong>
                    <p className="mb-0">{review.feedback}</p>
                    <p className="mb-0"><strong>Likes:</strong> {review.likes}</p> {/* Display likes */}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <Footer />
    </>
  );
};

export default PatientReviewsPage;
