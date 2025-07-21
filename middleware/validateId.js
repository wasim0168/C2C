const AppError = require('../utils/AppError');

const validateProductId = (req, res, next) => {
  const { id } = req.params;
  
  if (!id || !Number.isInteger(Number(id)) || Number(id) <= 0) {
    return next(new AppError('Invalid product ID format', 400));
  }
  
  next();
};

module.exports = validateProductId;