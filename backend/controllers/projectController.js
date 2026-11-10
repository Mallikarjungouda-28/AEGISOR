const fs = require('fs');
const mongoose = require('mongoose');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const {
  deleteProjectArchive,
  deleteProjectFolder
} = require('../services/storage/supabaseStorageService');

/**
 * @desc    Create a new project
 * @route   POST /api/projects
 * @access  Private
 */
const createProject = async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Project name is required'
      });
    }

    const project = await Project.create({
      name: name.trim(),
      description: description ? description.trim() : '',
      owner: req.user._id
    });

    return res.status(201).json({
      status: 'success',
      message: 'Project created successfully',
      data: { project }
    });
  } catch (error) {
    console.error(`[AEGISOR Project Error] Create: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error creating project'
    });
  }
};

/**
 * @desc    Get all projects belonging to the authenticated user
 * @route   GET /api/projects
 * @access  Private
 */
const getProjects = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip = (page - 1) * limit;

    const query = { owner: req.user._id };

    const [total, projects] = await Promise.all([
      Project.countDocuments(query),
      Project.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit)
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        projects
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Project Error] GetAll: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving projects'
    });
  }
};

/**
 * @desc    Get a single project by ID
 * @route   GET /api/projects/:id
 * @access  Private
 */
const getProjectById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid project ID format'
      });
    }

    const project = await Project.findById(id);

    if (!project) {
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    // Ownership verification
    if (!project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    return res.status(200).json({
      status: 'success',
      data: { project }
    });
  } catch (error) {
    console.error(`[AEGISOR Project Error] GetById: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving project'
    });
  }
};

/**
 * @desc    Update project name and description
 * @route   PUT /api/projects/:id
 * @access  Private
 */
const updateProject = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid project ID format'
      });
    }

    const project = await Project.findById(id);

    if (!project) {
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    if (!project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    if (name !== undefined) {
      if (typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          status: 'fail',
          message: 'Project name cannot be empty'
        });
      }
      project.name = name.trim();
    }

    if (description !== undefined) {
      project.description = typeof description === 'string' ? description.trim() : '';
    }

    await project.save();

    return res.status(200).json({
      status: 'success',
      message: 'Project updated successfully',
      data: { project }
    });
  } catch (error) {
    console.error(`[AEGISOR Project Error] Update: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error updating project'
    });
  }
};

/**
 * @desc    Delete project and its associated scans/findings/files
 * @route   DELETE /api/projects/:id
 * @access  Private
 */
const deleteProject = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid project ID format'
      });
    }

    const project = await Project.findById(id);

    if (!project) {
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    if (!project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    // Clean up extracted files on disk
    if (project.extractedPath && fs.existsSync(project.extractedPath)) {
      try {
        fs.rmSync(project.extractedPath, { recursive: true, force: true });
      } catch (err) {
        console.warn(`[Cleanup Warning] Could not remove ${project.extractedPath}: ${err.message}`);
      }
    }

    // Clean up Supabase Storage archive(s)
    try {
      if (project.storageKey) {
        await deleteProjectArchive(project.storageKey);
      }
      await deleteProjectFolder(project._id.toString());
    } catch (storageErr) {
      console.warn(`[Supabase Storage Warning] Cleanup failed for project ${project._id}: ${storageErr.message}`);
    }

    // Cascade delete scans and vulnerabilities
    await Vulnerability.deleteMany({ project: project._id });
    await Scan.deleteMany({ project: project._id });
    await Project.findByIdAndDelete(project._id);

    return res.status(200).json({
      status: 'success',
      message: 'Project and all associated scans have been permanently deleted'
    });
  } catch (error) {
    console.error(`[AEGISOR Project Error] Delete: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error deleting project'
    });
  }
};

module.exports = {
  createProject,
  getProjects,
  getProjectById,
  updateProject,
  deleteProject
};

