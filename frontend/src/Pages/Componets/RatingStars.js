// RatingStars.js
import React from 'react';
import { FaStar } from 'react-icons/fa'; // Importing star icon

const RatingStars = ({ rating }) => {
  const stars = [];

  for (let i = 1; i <= 5; i++) {
    stars.push(
      <FaStar
        key={i}
        className="star"
        color={i <= rating ? "#ffc107" : "#e4e5e9"} // Gold for filled stars, gray for empty
        size={24} // Adjust size as needed
      />
    );
  }

  return <div>{stars}</div>;
};

export default RatingStars;
