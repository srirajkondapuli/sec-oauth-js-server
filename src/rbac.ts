import { AccessControl } from 'accesscontrol';
import { logger } from './logger';
import * as permissions from './permissions.json';
export class Rbac {
    private ac: AccessControl;
    constructor() {
        this.ac = new AccessControl();
        this.ac.grant('basic').readOwn('profile').createOwn('profile').updateOwn('profile');

        this.ac.grant('supervisor').extend('basic').readAny('profile').createAny('profile');

        this.ac.grant('admin').extend('basic').extend('supervisor').updateAny('profile').deleteAny('profile');
        this.ac.grant('Slack_Users_S').readOwn('profile').updateOwn('profile').createOwn('profile').deleteOwn('profile');
        this.ac.grant('SecureAuth_Restrict_s').readOwn('profile').updateOwn('profile').createOwn('profile').deleteOwn('profile');
        
        for(let role of permissions.roles){
            logger.info('Loading Permissions : ' + JSON.stringify(role));
            for(let grant of role.permissions.methods){

                if(grant === 'GET'){
                    this.ac.grant(role.name).readOwn(role.permissions.path);
                }
                if(grant === 'POST'){
                    this.ac.grant(role.name).createOwn(role.permissions.path);
                }
                if(grant === 'PUT'){
                    this.ac.grant(role.name).updateOwn(role.permissions.path);
                }
                if(grant === 'DELETE'){
                    this.ac.grant(role.name).deleteOwn(role.permissions.path);
                }
            }
        }



    }
    isAuthorized = (user: string, operation: string, resource: string): any => {
        let permission: any;
        try {
            const result = this.ac.can(user);

            if (result) {
                permission = result.readOwn('profile');
            }
        } catch (error) {

            logger.error('Role Not Found Error : ' + error);
            permission = {
                "not_found" : true
            }
            
        }



        return permission;
    };
    isAuthorizedMultiple = (roles: string[], operation: string, resource: string): any => {
        let permission: any;
        try {
            permission= this.ac.can(roles).createOwn('profile');
 
        } catch (error) {

            logger.error('Can Error B: ' + error);
            permission = {
                "not_found" : true
            }
            
        }


        logger.info('Permission Returned : ' + JSON.stringify(permission));
        return permission;
    };

    isUserAuthorized = (user: any, operation: string, resource: string): any => {
        logger.info('Groups : ' + JSON.stringify(user));
        let permission:any;

        if (user.groups) {
            const authorized: boolean = false;
            const groups = String(user.groups);
            const roles = groups.split(',');
            logger.info('Roles : ' + roles);
            for(let role of roles){
                permission= this.isAuthorized(role,'createOwn', 'profile');
                logger.info('Permission Returned : ' + JSON.stringify(permission));
                if (permission.granted) {
                    logger.info('Permision Granded : ' + permission.granted + ' Breaking out of loop');
                    break;
                } else {
                    logger.info('Permissions not found for user role ' + role);
                }
            }

        } else {
            logger.info('User Groups not found!!');
        }
        logger.info('Permision Granded Outside: ' + permission.granted);

        return permission;

    };

    isUserAuthorizedMultiple = (user: any, operation: string, resource: string): any => {
        logger.info('Method: isUserAuthorizedMultiple');
        logger.info('Groups : ' + user.groups);
        const groupsStr: string = String(user.groups);
        if (groupsStr.length > 0) {
            const authorized: boolean = false;

            const roles = groupsStr.split(',');
            logger.info('Roles : ' + roles);
            try {
                const permissionResult = this.isAuthorizedMultiple(roles, 'createOwn', 'profile');
                logger.info('Permission Result : ' + JSON.stringify(permissionResult));

            } catch (error) {
                logger.error(error);
            }
            

        } else {
            logger.info('User Groups not found!!');
        }
        const permission = this.ac.can('basic').readOwn('profile');
        logger.info('Returning Permision Granded : ' + permission.granted);
        return permission;
    };

    getGrants = () => {
        return this.ac.getGrants();
    };
    getRoles = () => {
        return this.ac.getRoles();
    };
}
