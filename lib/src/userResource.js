var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
var authorizedResource_1 = require('./authorizedResource');
var mongoose_1 = require('mongoose');
var auth = require('./authentication');
var UserResource = (function (_super) {
    __extends(UserResource, _super);
    function UserResource() {
        _super.apply(this, arguments);
        this.permissions = {
            getAll: [authorizedResource_1.ROLES.USER, authorizedResource_1.ROLES.SUPER_USER, authorizedResource_1.ROLES.MODERATOR, authorizedResource_1.ROLES.ADMIN],
            getById: [authorizedResource_1.ROLES.USER, authorizedResource_1.ROLES.SUPER_USER, authorizedResource_1.ROLES.MODERATOR, authorizedResource_1.ROLES.ADMIN],
            create: [],
            update: [authorizedResource_1.ROLES.MODERATOR, authorizedResource_1.ROLES.ADMIN],
            del: [authorizedResource_1.ROLES.ADMIN]
        };
    }
    UserResource.prototype.createModel = function (resDef) {
        this.ensureBaseUserModel(resDef.model);
        resDef.model.roles = [{
                type: mongoose_1.Schema.Types.ObjectId,
                ref: 'Role'
            }];
        this.createRoleModel();
        return _super.prototype.createModel.call(this, resDef);
    };
    UserResource.prototype.ensureBaseUserModel = function (model) {
        model.userName = String;
        model.password = String;
    };
    UserResource.prototype.createRoleModel = function () {
        var roleSchema = new mongoose_1.Schema({
            name: String
        });
        this.db.model('Role', roleSchema);
    };
    UserResource.prototype.setupRoutes = function () {
        var _this = this;
        _super.prototype.setupRoutes.call(this);
        this.router
            .route(this.url + '/login')
            .post(function (req, res) { return _this.login(req, res); });
    };
    UserResource.prototype.isSelf = function (req) {
        var authToken = req.header('Authorization');
        var tokenDetails = auth.decryptAuthToken(authToken);
        return tokenDetails.id === req.params.userId;
    };
    UserResource.prototype.create = function (req, res) {
        req.body.password = auth.encryptPassword(req.body.password);
        _super.prototype.create.call(this, req, res);
    };
    UserResource.prototype.update = function (req, res) {
        var _this = this;
        delete req.body.password;
        this.isAuthorized(req, this.permissions.update)
            .then(function () { return _this.baseUpdate(req, res); }, function (err) {
            if (err.message === 'unauthorized' && _this.isSelf(req)) {
                _this.baseUpdate(req, res);
            }
            else {
                _this.sendUnauthorized(err, res);
            }
        });
    };
    UserResource.prototype.del = function (req, res) {
        var _this = this;
        this.isAuthorized(req, this.permissions.del)
            .then(function () { return _this.baseDel(req, res); }, function (err) {
            if (err.message === 'unauthorized' && _this.isSelf(req)) {
                _this.baseDel(req, res);
            }
            else {
                _this.sendUnauthorized(err, res);
            }
        });
    };
    UserResource.prototype.login = function (req, res) {
        var _this = this;
        var password = auth.encryptPassword(req.body.password);
        this.model.findOne({
            userName: new RegExp('^' + req.body.userName + '$', 'i'),
            password: password
        }).exec()
            .then(function (user) {
            if (!!user) {
                res.send({
                    user: user,
                    authToken: auth.createAuthToken(user._id.toString())
                });
            }
            else {
                _this.sendUnauthorized(new Error('incorrect login'), res);
            }
        }, function () { return _this.sendUnauthorized(new Error('cannot perform login'), res); });
    };
    return UserResource;
})(authorizedResource_1.AuthorizedResource);
module.exports = UserResource;
