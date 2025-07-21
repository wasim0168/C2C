const Product = require('../models/Product');
const AppError = require('../utils/AppError');

const validateProductId = (req, res, next) => {
  if (!Product.validateId(req.params.id)) {
    return next(new AppError('Invalid product ID format', 400));
  }
  next();
};

module.exports = validateProductId;