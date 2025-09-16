const express = require('express');
const User = require('../models/User');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// Aplicar autenticação e autorização para todas as rotas
router.use(authenticate);
router.use(authorize(['admin']));

// GET /api/users - Listar todos os usuários
router.get('/', async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/users/:id - Obter usuário específico
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id - Atualizar usuário
router.put('/:id', async (req, res) => {
  try {
    const { name, email, role } = req.body;
    
    // Não permitir que o usuário altere seu próprio papel
    if (req.params.id === req.user._id.toString() && role !== req.user.role) {
      return res.status(400).json({ error: 'Não é possível alterar seu próprio papel' });
    }

    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (role) updateData.role = role;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json(user);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email já está em uso' });
    }
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id - Excluir usuário
router.delete('/:id', async (req, res) => {
  try {
    // Não permitir que o usuário exclua a si mesmo
    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({ error: 'Não é possível excluir sua própria conta' });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

