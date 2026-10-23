import { Request, Response, Router } from 'express';
import { requireAuth } from '../auth';

const router = Router();

function getOrder(req: Request, res: Response) {
  res.json({ id: req.params.id });
}

function deleteOrder(req: Request, res: Response) {
  res.status(204).end();
}

router.route('/:id').get(requireAuth, getOrder).delete(deleteOrder);

export default router;
