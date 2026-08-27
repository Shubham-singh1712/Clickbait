import { Router } from 'express';
import { institutionController } from '../controllers/institution.controller';

const router = Router();

// POST /api/institutions - Register institution
router.post('/', (req, res, next) => institutionController.createInstitution(req, res, next));

// POST /api/institutions/:id/keys - Register trusted public key
router.post('/:id/keys', (req, res, next) => institutionController.registerPublicKey(req, res, next));

// GET /api/institutions/:id/keys/active - Get active trusted public key
router.get('/:id/keys/active', (req, res, next) => institutionController.getActivePublicKey(req, res, next));

// POST /api/institutions/:id/keys/:keyId/revoke - Revoke public key
router.post('/:id/keys/:keyId/revoke', (req, res, next) => institutionController.revokePublicKey(req, res, next));

export default router;
