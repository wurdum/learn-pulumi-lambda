import * as apigateway from "@pulumi/aws-apigateway";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import * as pulumi from "@pulumi/pulumi";
import * as jwt from "jsonwebtoken";
import * as jwksClient from "jwks-rsa";
import * as util from "util";

const config = new pulumi.Config();
const jwksUri = config.require("jwksUri");
const audience = config.require("audience");
const issuer = config.require("issuer");

const authorizerLambda = new aws.lambda.CallbackFunction("authorizerLambda", {
    callback: async (event: awsx.classic.apigateway.AuthorizerEvent) => {
        try {
            const verifiedJWT = await authenticate(event);

            return {
                principalId: verifiedJWT.sub,
                policyDocument: {
                    Version: "2012-10-17",
                    Statement: [
                        {
                            Action: "execute-api:Invoke",
                            Effect: "Allow",
                            Resource: event.methodArn,
                        },
                    ],
                },
            };
        }
        catch (err) {
            console.log(err);
            // Tells API Gateway to return a 401 Unauthorized response
            throw new Error("Unauthorized");
        }
    }
});

const authorizer = new aws.lambda.CallbackFunction("authorizer", {
    callback: async (event: awsx.classic.apigateway.AuthorizerEvent, context) => {
        const effect = event.headers?.Authorization === "token a-good-token" ? "Allow" : "Deny";

        return {
            principalId: "my-user",
            policyDocument: {
                Version: "2012-10-17",
                Statement: [
                    {
                        Action: "execute-api:Invoke",
                        Effect: effect,
                        Resource: event.methodArn,
                    },
                ],
            },
        };
    },
});

// A Lambda function to invoke
const fn = new aws.lambda.CallbackFunction("fn", {
    callback: async (ev, ctx) => {
        return {
            statusCode: 200,
            body: new Date().toISOString(),
        };
    }
})

// A REST API to route requests to HTML content and the Lambda function
const api = new apigateway.RestAPI("api", {
    routes: [
        { path: "/", localPath: "www"},
        {
            path: "/date",
            method: "GET",
            eventHandler: fn,
            authorizers: [
                // {
                //     authType: "custom",
                //     parameterName: "Authorization",
                //     type: "request",
                //     identitySource: ["method.request.header.Authorization"],
                //     handler: authorizer,
                // },
                {
                    authType: "custom",
                    parameterName: "Authorization",
                    type: "request",
                    identitySource: ["method.request.header.Authorization"],
                    handler: authorizerLambda,
                    identityValidationExpression: "^Bearer [-0-9a-zA-Z\._]*$",
                    authorizerResultTtlInSeconds: 3600,
                }
            ]
            // authorizers: [
            //     awsx.classic.apigateway.getTokenLambdaAuthorizer({
            //         authorizerName: "jwt-rsa-custom-authorizer",
            //         header: "Authorization",
            //         handler: authorizerLambda,
            //         identityValidationExpression: "^Bearer [-0-9a-zA-Z\._]*$",
            //         authorizerResultTtlInSeconds: 3600,
            //     })
            // ]
        },
    ],
});

// The URL at which the REST API will be served.
export const url = api.url;

function getToken(event: awsx.classic.apigateway.AuthorizerEvent): string {
    if (!event.type || event.type !== "TOKEN") {
        throw new Error('Expected "event.type" parameter to have value "TOKEN"');
    }

    const tokenString = event.authorizationToken;
    if (!tokenString) {
        throw new Error('Expected "event.authorizationToken" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }

    return match[1];
}

async function authenticate(event: awsx.classic.apigateway.AuthorizerEvent): Promise<VerifiedJWT> {
    console.log(event);
    const token = getToken(event);

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === "string" || !decoded.header || !decoded.header.kid) {
        throw new Error("invalid token");
    }

    const client = jwksClient({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10, // Default value
        jwksUri: jwksUri,
    });

    const key = await util.promisify(client.getSigningKey)(decoded.header.kid);
    if (!key) {
        throw new Error("could not get key");
    }

    const signingKey = key.getPublicKey();
    if (!signingKey) {
        throw new Error("could not get signing key");
    }

    const verifiedJWT = await jwt.verify(token, signingKey, { audience, issuer });
    if (!verifiedJWT || typeof verifiedJWT === "string" || !isVerifiedJWT(verifiedJWT)) {
        throw new Error("could not verify JWT");
    }

    return verifiedJWT;
}

interface VerifiedJWT {
    sub: string;
}

function isVerifiedJWT(toBeDetermined: VerifiedJWT | Object): toBeDetermined is VerifiedJWT {
    return (<VerifiedJWT>toBeDetermined).sub !== undefined;
}
