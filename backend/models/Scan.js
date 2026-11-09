const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema(
  {
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: [true, 'Project reference is required'],
      index: true
    },
    initiatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User reference is required'],
      index: true
    },
    status: {
      type: String,
      enum: {
        values: ['pending', 'processing', 'completed', 'failed'],
        message: '{VALUE} is not a valid scan status'
      },
      default: 'pending',
      index: true
    },
    securityScore: {
      type: Number,
      min: [0, 'Security score cannot be less than 0'],
      max: [100, 'Security score cannot exceed 100'],
      default: null
    },
    totalVulnerabilities: {
      type: Number,
      default: 0,
      min: [0, 'Total vulnerabilities cannot be negative']
    },
    scanStartedAt: {
      type: Date,
      default: null
    },
    scanCompletedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

// Compound index for querying scans by project sorted by newest
scanSchema.index({ project: 1, createdAt: -1 });

module.exports = mongoose.model('Scan', scanSchema);

