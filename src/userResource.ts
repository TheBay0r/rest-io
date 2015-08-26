import {AuthorizedResource, IMethodAccess, ROLES} from './authorizedResource';
import {Resource, IResource} from './resource';
import {Request, Router, Application, Response} from 'express';
import {Model, Schema} from 'mongoose';
import auth = require('./authentication');

class UserResource extends AuthorizedResource {

  permissions: IMethodAccess = {
    getAll: [ROLES.USER, ROLES.SUPER_USER, ROLES.MODERATOR, ROLES.ADMIN],
    getById: [ROLES.USER, ROLES.SUPER_USER, ROLES.MODERATOR, ROLES.ADMIN],
    create: [],
    update: [ROLES.ADMIN],
    del: [ROLES.ADMIN]
  }

  createModel(resDef: IResource) {
    this.ensureBaseUserModel(resDef.model);
    resDef.model.roles = [{
      type: Schema.Types.ObjectId,
      ref: 'Role'
    }];
    this.createRoleModel();
    return super.createModel(resDef);
  }

  ensureBaseUserModel(model: any) {
    model.userName = String;
    model.password = String;
  }

  createRoleModel() {
    var roleSchema = new Schema({
      name: String
    });
    this.db.model('Role', roleSchema);
    // create the default roles if they do not exist
  }

  setupRoutes() {
    super.setupRoutes();
    this.router
      .route(this.url + '/login')
      .post((req, res) => this.login(req, res));
  }

  isSelf(req: Request) {
    var authToken = req.header('Authorization');
    var tokenDetails = auth.decryptAuthToken(authToken);
    return tokenDetails.id === req.params.userId;
  }

  create(req: Request, res: Response) {
    req.body.password = auth.encryptPassword(req.body.password);
    // Make sure the roles can only be added by authorized users
    // Find the roles and push the role id
    super.create(req, res);
  }

  update(req: Request, res: Response) {
    delete req.body.password;
    // Make sure the roles can only be updated by authorized users
    // Find the roles and push the role id
    this.isAuthorized(req, this.permissions.update)
      .then(() => this.db.model('Role').find({}).exec())
      .then((roles: Array<any>) => {
        var roleIds = [];
        if (!!req.body.roles) {
          req.body.roles.forEach((role: string) => {
            roles.forEach((dbRole) => {
              if (dbRole.name === role) {
                roleIds.push(dbRole._id);
                return false;
              }
            });
          });
          req.body.roles = roleIds;
        }
      })
      .then(() => this.baseUpdate(req, res),
      (err) => {
        if (err.message === 'unauthorized' && this.isSelf(req)) {
          delete req.body.roles;
          this.baseUpdate(req, res);
        } else {
          this.sendUnauthorized(err, res);
        }
      });
  }

  del(req: Request, res: Response) {
    this.isAuthorized(req, this.permissions.del)
      .then(() => this.baseDel(req, res),
      (err) => {
        if (err.message === 'unauthorized' && this.isSelf(req)) {
          this.baseDel(req, res);
        } else {
          this.sendUnauthorized(err, res);
        }
      });
  }

  login(req: Request, res: Response) {
    var password = auth.encryptPassword(req.body.password);
    this.model.findOne({
      userName: new RegExp('^' + req.body.userName + '$', 'i'),
      password: password
    }).exec()
      .then((user: any) => {
        if (!!user) {
          res.send({
            user: user,
            authToken: auth.createAuthToken(user._id.toString())
          });
        } else {
          this.sendUnauthorized(new Error('incorrect login'), res);
        }
      }, () => this.sendUnauthorized(new Error('cannot perform login'), res));
  }
}

export = UserResource;
