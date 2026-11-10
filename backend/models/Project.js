const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Project name is required'],
      trim: true,
      maxlength: [150, 'Project name cannot exceed 150 characters']
    },
    description: {
      type: String,
      trim: true,
      default: '',
      maxlength: [1000, 'Description cannot exceed 1000 characters']
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Project owner is required'],
      index: true
    },
    originalFileName: {
      type: String,
      trim: true,
      default: null
    },
    programmingLanguages: {
      type: [String],
      default: []
    },
    frameworks: {
      type: [String],
      default: []
    },
    manifestFiles: {
      type: [String],
      default: []
    },
    entryPoints: {
      type: [String],
      default: []
    },
    extractedPath: {
      type: String,
      default: null
    },
    storageKey: {
      type: String,
      default: null
    },
    storageBucket: {
      type: String,
      default: 'project-archives'
    },
    fileCount: {
      type: Number,
      default: 0
    },
    totalLinesOfCode: {
      type: Number,
      default: 0
    },
    lastScanDate: {
      type: Date,
      default: null
    },
    latestSecurityScore: {
      type: Number,
      default: null
    }
  },
  {
    timestamps: true
  }
);

// Compound index for querying user projects sorted by creation date
projectSchema.index({ owner: 1, createdAt: -1 });

module.exports = mongoose.model('Project', projectSchema);
