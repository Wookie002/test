const RBAC = require('easy-rbac');
const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient();
const jwtDecode = require('jwt-decode');
const actionMap = {
    'GET' : 'read',
    'POST' : 'write',
    'DELETE' : 'delete',
};

exports.handler = async (event, context, callback) => {
    let error = null;
    
    if (!event.headers['token-id']) {
        error = new Error("Required token-id is missing in headers.");
        callback(error);
    }
    
    const userId = (jwtDecode(event.headers['token-id'])).sub;

    if (!userId || !event.path || !event.method) {
        error = new Error("Required parameters are missing. \n userId:" + userId + ", \n path:" + event.path + ", \n method:" + event.method);
        callback(error);
    }

    const userRole = await getUserRole(userId);
    
    if (userRole) {
        const rule = await getRules(userRole.AGENCY, userRole.ROLE);
        
        let options = {};
        const actions = rule.ACTION.split(':');
        let cans = actions.map((item) => rule.PATH + ":" + item);
        const agencyRole = rule.AGENCY + ":" + rule.ROLE;
        let conditions = null;
        let equalToReqMethod = null;
        
        if (rule.CONDITIONS && rule.CONDITIONS.length > 0) {
            const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
            conditions = rule.CONDITIONS.map((item) => {
                item['name'] = item['name'] + ':' + item['method'];
                item['when'] = new AsyncFunction('params', "return " + item['when']);
                return item;
            });
            equalToReqMethod = conditions.some( (item) => item.method === actionMap[event.method]);
            cans = cans.concat(conditions);
        }
        
        options[agencyRole] = {'can':cans};
        const easy_rbac = new RBAC(options);

        if (equalToReqMethod) {
            
            let contentId = null;
            if(actionMap[event.method] === "read" && event.query.contentId) {
                contentId = event.query.contentId;
            } else if (event.body.contentId) {
                contentId = event.body.contentId;
            }
            
            if (!contentId) {
                error = new Error("Required parameter contentId is missing.");
                callback(error);
                return;
            }
            easy_rbac.can(agencyRole, event.path + ':' + actionMap[event.method], {'userId': userId, 'contentId': contentId})
            .then(result => {
                console.log('rbac result 1', result);
                callback(null, result);
            })
            .catch(err => {
                error = new Error(err);
                callback(error);
            });
        } else {
            easy_rbac.can(agencyRole, event.path + ':' + actionMap[event.method])
            .then(result => {
                console.log('rbac result 2', result);
                callback(null, result);
            })
            .catch(err => {
                error = new Error(err);
                callback(error);
            });
        }
    } else {
        callback(null, "false");
    }
};

var getUserRole = async (userId) => {
    const param = {
        TableName : 'USER_ROLE',
        FilterExpression : 'USER_ID = :user_id',
        ExpressionAttributeValues: {
            ':user_id': userId
        }
    };
    
    const userRoles = (await documentClient.scan(param).promise()).Items;
    
    return userRoles && userRoles.length > 0 ? userRoles[0] : null;
};

var getRules = async (agency, role) => {
    const param = {
        TableName : 'RULE',
        FilterExpression : 'AGENCY = :agency and #role = :role',
        ExpressionAttributeValues: {
            ':agency': agency,
            ':role': role
        },
        ExpressionAttributeNames: {
            '#role': 'ROLE'
        }
    };
    
    const rules = (await documentClient.scan(param).promise()).Items;
    
    return rules && rules.length > 0 ? rules[0] : null;
};