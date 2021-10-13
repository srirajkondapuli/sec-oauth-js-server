import { AccessControl } from 'accesscontrol';
const ac = new AccessControl();

exports.roles = () => {
  ac.grant('basic').readOwn('profile').createOwn('profile').updateOwn('profile');

  ac.grant('supervisor').extend('basic').readAny('profile');

  ac.grant('admin').extend('basic').extend('supervisor').updateAny('profile').deleteAny('profile');

  return ac;
};
