import admin from "firebase-admin";
import * as functions from "firebase-functions";
import {CallableContext} from "firebase-functions/lib/common/providers/https";
import creds from "./credentials.json";

/**
 * Application entrypoint.
 *
 * This function should initialize all the services that will be used during
 * the Cloud Function execution.
 */
function main() {
  admin.initializeApp({
    ...creds,
    credential: admin.credential.cert({
      clientEmail: creds.client_email,
      privateKey: creds.private_key,
      projectId: creds.project_id,
    }),
  });

}

main();

function requireAuthenticated(context: CallableContext): string {
  const uid = context.auth?.uid;
  if (uid == null) {
    throw new functions.https.HttpsError("permission-denied", "Not authenticated");
  }
  return uid;
}

// TODO Set proper reference to role
const roleTable: string = "..."
const roleColumn: string = "..."

/**
 * Passing `undefined` to [expectedRole] turns the function public (anyone in the internet can call it).
 * Passing `null` to [expectedRole] turns the function protected (only authenticated accounts can call it).
 * Passing a `string` to [expectedRole] turns function private (only accounts with the given role can call it).
 */
async function requireRole(context: CallableContext, expectedRole: string | undefined | null): Promise<void> {
  if (expectedRole === undefined) return;

  const uid = requireAuthenticated(context);
  if (expectedRole === null) return;
  const actualRole = await admin.database()
      .ref(roleTable)
      .child(uid)
      .child(roleColumn)
      .get()
      .then((snapshot: admin.database.DataSnapshot) => snapshot.val() as string);

  if (actualRole !== expectedRole) {
    throw new functions.https.HttpsError(
        "permission-denied",
        `Wrong role, expected ${expectedRole}, got ${actualRole}`,
    );
  }
}

async function createUser(email: string, password: string): Promise<string> {
  const record = await admin.auth()
      .createUser({
        email: email,
        password: password,
        providerToLink: {
          email: email,
          uid: email,
          providerId: "password",
        },
      });
  return record.uid;
}

async function deleteUser(uid: string): Promise<void> {
  await admin.auth().deleteUser(uid);
}

export const registerUser = functions.https
    .onCall(async (request, context) => {
      // TODO Set proper rule
      await requireRole(context, undefined);

      const data: { email: string, password: string } = request.body;
      return await createUser(data.email, data.password)
    });

export const unregisterUser = functions.https
    .onCall(async (request, context) => {
      // TODO Set proper rule
      await requireRole(context, undefined);

      const data: { uid: string } = request.body;
      await deleteUser(data.uid);
    });
