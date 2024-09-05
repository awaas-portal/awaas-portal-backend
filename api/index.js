const admin = require("firebase-admin");
const express = require("express");
const bodyParser = require("body-parser");
const { DateTime } = require("luxon");
const dotenv = require("dotenv");
const multer = require("multer");
const cors = require("cors");
dotenv.config();
const serverless = require("serverless-http");

const WAITING_LIST_SELECTOR = "WAITING_LIST";
const SERIAL_NO_SELECTOR = "SERIAL";
const STORAGE_BUCKET = "awaas-portal.appspot.com";
const NOTIFICATIONS_COLLECTION = "notifications";
const ACTIVE_APPLICATIONS_COLLECTION = "activeApplications";
const WAITING_COLLECTION = "waiting";
const ARCHIVED_APPLICATIONS_COLLECTION = "archivedApplications";
const upload = multer({ storage: multer.memoryStorage() });

const credentials = {
  type: process.env.type,
  project_id: process.env.project_id,
  private_key_id: process.env.private_key_id,
  private_key: process.env.private_key,
  client_email: process.env.client_email,
  client_id: process.env.client_id,
  auth_uri: process.env.auth_uri,
  token_uri: process.env.token_uri,
  auth_provider_x509_cert_url: process.env.auth_provider_x509_cert_url,
  client_x509_cert_url: process.env.client_x509_cert_url,
  universe_domain: process.env.universe_domain,
};

const firebaseApp = admin.initializeApp({
  credential: admin.credential.cert(credentials),
});
const db = admin.firestore();
const app = express();
const corsOptions = {
  origin: ["http://localhost:3000", process.env.frontend_url], // Specify the allowed origin
  credentials: true, // Allow credentials
};

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
// app.use(methodOverride());

const updateRow = async (collection, column, id, data) => {
  try {
    const row = await db
      .collection(collection)
      .where(column, "==", id)
      .limit(1)
      .get();
    if (row.docs.length) {
      return row.docs[0].ref.update(data);
    } else {
      throw new Error("No application found");
    }
  } catch (e) {
    throw new Error(e);
  }
};

const getRow = async (collection, column, id) => {
  try {
    return db.collection(collection).where(column, "==", id).limit(1).get();
  } catch (e) {
    throw new Error(e);
  }
};

const getRows = async (collection) => {
  try {
    return db.collection(collection).get();
  } catch (e) {
    throw new Error(e);
  }
};

const deleteRow = async (collection, column, id) => {
  try {
    return (
      await db.collection(collection).where(column, "==", id).limit(1).get()
    ).docs[0].ref.delete();
  } catch (e) {
    throw new Error(e);
  }
};

/**
 *
 * @param {boolean} status
 * @param {string} message
 * @return {JSON}
 */
function resp(status, message) {
  return {
    status: status,
    message: message || "",
  };
}

// ------------------ Authentication ---------------- //

const authenticateManager = async (req, res, next) => {
  const authToken = req.get("Authorization");
  if (!authToken || !authToken.startsWith("Bearer ")) {
    return res.status(401).json(resp(false, "Unauthorized"));
  }
  const idToken = authToken.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Error verifying ID token:", error);
    return res.status(401).json(resp(false, "Unauthorized"));
  }
};

const authenticateAdmin = async (req, res, next) => {
  const authToken = req.get("Authorization");
  if (!authToken || !authToken.startsWith("Bearer ")) {
    return res.status(401).json(resp(false, "Unauthorized"));
  }
  const idToken = authToken.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    if (decodedToken.role !== "admin") {
      return res.status(401).json(resp(false, "Unauthorized"));
    }
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Error verifying ID token:", error);
    return res.status(401).json(resp(false, "Unauthorized"));
  }
};


app.post("/auth/manager/register", authenticateAdmin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await admin.auth().createUser({
      email,
      password,
    });
    await admin.auth().setCustomUserClaims(user.uid, { role: "manager" });
    return res.status(201).json(resp(true, user));
  } catch (error) {
    console.error("Error creating user:", error);
    return res.status(500).json(resp(false, error));
  }
});

app.delete("/auth/manager/delete", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.query;
    await admin.auth().deleteUser(id);
    return res.status(201).json(resp(true, "User deleted successfully"));
  } catch (error) {
    if (error.code === "auth/user-not-found") {
      return res.status(404).json(resp(false, "User not found"));
    }
    console.error("Error deleting user:", error);
    return res.status(500).json(resp(false, error.message));
  }
});

app.get("/auth/manager/all", authenticateAdmin, async (req, res) => {
  try {
    const users = await admin.auth().listUsers();
    const managers = users.users.filter((user) => {
      if (user.customClaims && user.customClaims.role === "manager") {
        return user;
      }
    });
    return res.status(200).json(resp(true, managers));
  } catch (error) {
    console.error("Error fetching users:", error);
    return res.status(500).json(resp(false, error));
  }
});

app.get("/auth/check", async (req, res) => {
  try {
    const authToken = req.get("Authorization");
    if (!authToken || !authToken.startsWith("Bearer ")) {
      return res.status(401).json(resp(false, "Unauthorized"));
    }
    const idToken = authToken.split("Bearer ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    return res.status(200).json(resp(true, decodedToken));
  } catch (error) {
    console.error("Error verifying ID token:", error);
    return res.status(401).json(resp(false, "Unauthorized"));
  }
});

app.get("/auth/log", authenticateManager, async (req, res) => {
  try {
    const email = req.user.firebase.identities.email;
    const currentTime = DateTime.now().setZone("Asia/Kolkata").toISO();
    const previous = await db.collection("login").where("email", "==", email).limit(1).get();
    if (!previous.docs.length) {
      await db.collection("login").add({ email: email, time: currentTime });
      return res.status(200).json(resp(false, { time: "" }));
    }
    const log_resp = resp(true, previous.docs[0].data());
    previous.docs[0].ref.update({ time: currentTime });
    return res.status(200).json(log_resp);
  } catch (error) {
    console.error("Error fetching logs:", error);
    return res.status(500).json(resp(false, error));
  }
});

// ------------------ Active Applications ---------------- //
// Add many applications
app.post("/application/active/create/many", authenticateManager, async (req, res) => {
  try {
    // parse applications
    const { applications } = req.body;

    // get the waiting list numbers
    const waitingDoc = await getRow(
      WAITING_COLLECTION,
      "selector",
      WAITING_LIST_SELECTOR
    );

    // get the serial number
    const serialDoc = await getRow(
      WAITING_COLLECTION,
      "selector",
      SERIAL_NO_SELECTOR
    );

    // actual waiting list document
    const waitingList = waitingDoc.docs[0].data();
    let serialNo = serialDoc.docs[0].data().serial;
    const modifiedApplications = applications.map((application) => {
      if (!waitingList[application.rank]) {
        waitingList[application.rank] = 1;
      }
      if (application.initialWaiting && application.initialWaiting !== -1) {
        waitingList[application.rank] = Math.max(
          waitingList[application.rank],
          application["currentWaiting"]
        );
        // assign serial number
        if (application.serialNo && application.serialNo !== -1) {
          serialNo = Math.max(serialNo, application.serialNo + 1);
          return application;
        } else {
          application.serialNo = serialNo;
          serialNo += 1;
          return application;
        }
        // serial number logic ends
      } else {
        const doc = {
          ...application,
          initialWaiting: waitingList[application.rank],
          currentWaiting: waitingList[application.rank],
        };
        waitingList[application.rank] += 1;
        if (application.serialNo && application.serialNo !== -1) {
          serialNo = Math.max(serialNo, application.serialNo + 1);
          return doc;
        } else {
          doc.serialNo = serialNo;
          serialNo += 1;
          return doc;
        }
      }
    });
    const batch = db.batch();
    const ids = [];
    modifiedApplications.forEach((application) => {
      const ref = db.collection(ACTIVE_APPLICATIONS_COLLECTION).doc();
      batch.set(ref, application);
      ids.push(ref.id);
    });
    batch.update(waitingDoc.docs[0].ref, waitingList);
    batch.update(serialDoc.docs[0].ref, { serial: serialNo });
    await batch.commit();
    return res.status(201).json(resp(true, ids));
  } catch (error) {
    return res.status(500).json(resp(false, error.message));
  }
});

// Read operation?id=123&mobile=
app.get("/application/active/info", async (req, res) => {
  if (!req.query.id) {
    return res.status(400).json(resp(false, "Invalid request"));
  }
  try {
    const byPno = await db.collection(ACTIVE_APPLICATIONS_COLLECTION).where("pno", "==", req.query.id).limit(1).get();
    if (byPno.docs.length) {
      return res
        .status(200)
        .json(resp(true, { ...byPno.docs[0].data(), id: byPno.docs[0].id }));
    }
    return res.status(404).json(resp(false, "No application found"));
  } catch (error) {
    console.error("Error fetching applications:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

app.get("/application/active/all", authenticateManager, async (req, res) => {
  try {
    const snapshot = await getRows(ACTIVE_APPLICATIONS_COLLECTION);
    const applications = [];
    snapshot.forEach((doc) => {
      applications.push({ ...doc.data(), id: doc.id });
    });
    return res.status(200).json(resp(true, applications));
  } catch (error) {
    console.error("Error fetching applications:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Update operation
app.post("/application/update", authenticateManager, async (req, res) => {
  try {
    const { id, data } = req.body;
    await db.collection(ACTIVE_APPLICATIONS_COLLECTION).doc(id).update(data);
    return res.status(200).json(resp(true, "Application updated successfully"));
  } catch (error) {
    console.error("Error updating application:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Delete operation
app.delete("/application/delete", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.query;
    const deleteApplication = await db
      .collection(ACTIVE_APPLICATIONS_COLLECTION)
      .doc(id)
      .get();

    if (!deleteApplication.exists) {
      return res.status(404).json(resp(false, "No application found"));
    }

    const activeApplications = await db
      .collection(ACTIVE_APPLICATIONS_COLLECTION)
      .get();

    const batch = db.batch();
    // get the waiting list numbers
    const waitingDoc = await getRow(
      WAITING_COLLECTION,
      "selector",
      WAITING_LIST_SELECTOR
    );
    const waitingList = waitingDoc.docs[0].data();

    // find the number of changes and move them to ARCHIVED_APPLICATIONS_COLLECTION
    const deleteRank = deleteApplication.data()["rank"];
    activeApplications.docs.forEach((doc) => {
      if (deleteRank === doc.data()["rank"]) {
        const application = doc.data();
        if (application["currentWaiting"] > deleteApplication.data()["currentWaiting"]) {
          application["currentWaiting"] -= 1;
          batch.update(doc.ref, application);
        }
      }
    });

    // update the waiting list document
    waitingList[deleteRank] -= 1;

    batch.update(waitingDoc.docs[0].ref, waitingList);
    batch.delete(deleteApplication.ref);

    // commit the transaction
    await batch.commit();

    res.status(200).json(resp(true, "Application deleted successfully"));
  } catch (error) {
    console.error("Error deleting application:", error);
    res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Delete Many Applications
app.delete("/application/active/delete/many", authenticateAdmin, async (req, res) => {
  try {
    const { ids } = req.body;
    const batch = db.batch();

    // get all applications with the given pno
    const allotedApplications = await db
      .collection(ACTIVE_APPLICATIONS_COLLECTION)
      .where(admin.firestore.FieldPath.documentId(), "in", ids)
      .get();

    // get the waiting list numbers
    const waitingDoc = await getRow(
      WAITING_COLLECTION,
      "selector",
      WAITING_LIST_SELECTOR
    );
    const waitingList = waitingDoc.docs[0].data();

    // doc to maintain the waiting changes
    const waitingChanges = {};
    const currentWaitingDict = {};
    // find the number of changes and move them to ARCHIVED_APPLICATIONS_COLLECTION
    const deleteRefs = [];
    allotedApplications.docs.forEach((doc) => {
      const application = doc.data();
      if (!currentWaitingDict[application["rank"]]) {
        currentWaitingDict[application["rank"]] = [];
      }
      currentWaitingDict[application["rank"]].push(application["currentWaiting"]);
      deleteRefs.push(doc.ref);
      if (!waitingChanges[application.rank]) {
        waitingChanges[application.rank] = 0;
      }
      waitingChanges[application.rank] += 1;
    });

    // update the waiting list document
    Object.keys(waitingChanges).forEach((key) => {
      waitingList[key] -= waitingChanges[key];
    });

    batch.update(waitingDoc.docs[0].ref, waitingList);

    // update the waiting list of all pending applications
    const allActiveApplications = (
      await getRows(ACTIVE_APPLICATIONS_COLLECTION)
    ).docs;

    allActiveApplications.filter((application) => !ids.includes(application.id)).forEach((doc) => {
      const application = doc.data();
      let change = 0;
      Object.entries(currentWaitingDict).forEach(([key, value]) => {
        if (application["rank"] === key) {
          value.sort();
          value.forEach(val => {
            if (val < application["currentWaiting"]) {
              change += 1;
            } else {
              return;
            }
          })
        }
      });
      if (change) {
        application["currentWaiting"] -= change;
        batch.update(doc.ref, application);
      }
    });

    // commit the transaction
    deleteRefs.forEach((ref) => {
      batch.delete(ref);
    });
    await batch.commit();
    res.status(200).json(
      resp(true, {
        allotedApplications: ids,
      })
    );
  } catch (e) {
    console.error("Error in Allotment:", e);
    res.status(500).json(resp(false, e));
  }
});

// ------------------ Archived Applications ---------------- //

app.get("/application/archive/info", authenticateManager, async (req, res) => {
  try {
    const byPno = await getRow(
      ARCHIVED_APPLICATIONS_COLLECTION,
      "pno",
      req.query.id
    );
    if (byPno.docs.length) {
      return res
        .status(200)
        .json(resp(true, { ...byPno.docs[0].data(), id: byPno.docs[0].id }));
    }
    const byReferene = await getRow(
      ARCHIVED_APPLICATIONS_COLLECTION,
      "registrationNumber",
      req.query.id
    );
    if (byReferene.docs.length) {
      return res.status(200).json(
        resp(true, {
          ...byReferene.docs[0].data(),
          id: byReferene.docs[0].id,
        })
      );
    }
    return res.status(404).json(resp(false, "No application found"));
  } catch (error) {
    console.error("Error fetching applications:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

app.get("/application/archive/all", authenticateManager, async (req, res) => {
  try {
    const snapshot = await getRows(ARCHIVED_APPLICATIONS_COLLECTION);
    const applications = [];
    snapshot.forEach((doc) => {
      applications.push({ ...doc.data(), id: doc.id });
    });
    return res.status(200).json(resp(true, applications));
  } catch (error) {
    console.error("Error fetching applications:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

app.delete("/application/archive/delete/many", authenticateAdmin, async (req, res) => {
  try {
    const { ids } = req.body;
    const batch = db.batch();
    ids.forEach(async (id) => {
      const doc = db.collection(ARCHIVED_APPLICATIONS_COLLECTION).doc(id);
      batch.delete(doc);
    });
    await batch.commit();
    return res.status(200).json(resp(true, "Applications deleted successfully"));
  } catch (error) {
    console.error("Error deleting application:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// ------------------ Notices ---------------- //

// Get notice ?id=123
app.get("/notification/info", async (req, res) => {
  try {
    const notification = await db
      .collection(NOTIFICATIONS_COLLECTION)
      .doc(req.query.id)
      .get();
    if (notification.exists) {
      return res
        .status(200)
        .json(resp(true, { ...notification.data(), id: notification.id }));
    }
    return res.status(404).json(resp(false, "No notification found"));
  } catch (error) {
    console.error("Error fetching notification:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

app.get("/notification/all", async (req, res) => {
  try {
    const snapshot = await getRows(NOTIFICATIONS_COLLECTION);
    const notifications = [];
    snapshot.forEach((doc) => {
      notifications.push({
        id: doc.id,
        ...doc.data(),
      });
    });
    return res.status(200).json(resp(true, notifications));
  } catch (error) {
    console.error("Error fetching notifications:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Update operation
app.post("/notification/update", authenticateManager, async (req, res) => {
  try {
    const { id, data } = req.body;
    await db.collection(NOTIFICATIONS_COLLECTION).doc(id).update(data);
    return res
      .status(200)
      .json(resp(true, "Notification updated successfully"));
  } catch (error) {
    console.error("Error updating notification:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Delete operation ?id=123
app.delete("/notification/delete", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.query;
    const deleteRef = db.collection(NOTIFICATIONS_COLLECTION).doc(id);
    const document = await deleteRef.get();
    if (!document.exists) {
      return res.status(404).json(resp(false, "No notification found"));
    }
    const notification = document.data();
    await deleteRef.delete();
    const fileRef = admin
      .storage()
      .bucket(STORAGE_BUCKET)
      .file(notification.filename);
    if (fileRef.exists()) {
      await fileRef.delete();
    }
    return res
      .status(200)
      .json(resp(true, "Notification deleted successfully"));
  } catch (error) {
    console.error("Error deleting notification:", error);
    return res.status(500).json(resp(false, "Internal Server Error"));
  }
});

// Allot Notification
app.put("/notification/allot", authenticateManager, async (req, res) => {
  try {
    const { ids } = req.body;
    const batch = db.batch();

    // get all applications with the given pno
    const allotedApplications = await db
      .collection(ACTIVE_APPLICATIONS_COLLECTION)
      .where(admin.firestore.FieldPath.documentId(), "in", ids)
      .get();

    // get the waiting list numbers
    const waitingDoc = await getRow(
      WAITING_COLLECTION,
      "selector",
      WAITING_LIST_SELECTOR
    );
    const waitingList = waitingDoc.docs[0].data();

    // doc to maintain the waiting changes
    const waitingChanges = {};
    const currentWaitingDict = {};
    // find the number of changes and move them to ARCHIVED_APPLICATIONS_COLLECTION
    const deleteRefs = [];
    allotedApplications.docs.forEach((doc) => {
      const application = doc.data();
      if (!currentWaitingDict[application["rank"]]) {
        currentWaitingDict[application["rank"]] = [];
      }
      currentWaitingDict[application["rank"]].push(application["currentWaiting"]);
      const ref = db.collection(ARCHIVED_APPLICATIONS_COLLECTION).doc();
      batch.set(ref, application);
      deleteRefs.push(doc.ref);
      if (!waitingChanges[application.rank]) {
        waitingChanges[application.rank] = 0;
      }
      waitingChanges[application.rank] += 1;
    });

    // update the waiting list document
    Object.keys(waitingChanges).forEach((key) => {
      waitingList[key] -= waitingChanges[key];
    });

    batch.update(waitingDoc.docs[0].ref, waitingList);

    // update the waiting list of all pending applications
    const allActiveApplications = (
      await getRows(ACTIVE_APPLICATIONS_COLLECTION)
    ).docs;

    allActiveApplications.filter((application) => !ids.includes(application.id)).forEach((doc) => {
      const application = doc.data();
      let change = 0;
      Object.entries(currentWaitingDict).forEach(([key, value]) => {
        if (application["rank"] === key) {
          value.sort();
          value.forEach(val => {
            if (val < application["currentWaiting"]) {
              change += 1;
            } else {
              return;
            }
          })
        }
      });
      if (change) {
        application["currentWaiting"] -= change;
        batch.update(doc.ref, application);
      }
    });

    // commit the transaction
    deleteRefs.forEach((ref) => {
      batch.delete(ref);
    });
    await batch.commit();
    res.status(200).json(
      resp(true, {
        allotedApplications: ids,
      })
    );
  } catch (e) {
    console.error("Error in Allotment:", e);
    res.status(500).json(resp(false, e));
  }
});

app.put("/notification/general", authenticateManager, upload.single("file"), async (req, res) => {
  try {
    const { nanoid } = await require("nanoid");
    const file = req.file;
    if (!file) {
      return res.status(400).json(resp(false, "Invalid request"));
    }
    const body = JSON.parse(req.body["data"]);

    // upload file
    const uploadFilename = `${file.originalname.split(".")[0]}_${nanoid(5)}.${file.originalname.split(".")[1]
      }`;
    // upload file to storage
    const bucket = admin.storage().bucket(STORAGE_BUCKET);
    const uploadFile = bucket.file(uploadFilename);
    await uploadFile.save(file.buffer, {
      destination: uploadFilename,
      metadata: { contentType: file.mimetype },
    });
    await uploadFile.makePublic();
    const istTime = DateTime.now().setZone("Asia/Kolkata");

    const notification = {
      ...body,
      name: file.originalname,
      filename: uploadFilename,
      url: uploadFile.publicUrl(),
      releasedOn: istTime.toISO(),
    };

    const notificationRef = await db
      .collection(NOTIFICATIONS_COLLECTION)
      .add(notification);

    return res.status(200).json(
      resp(true, {
        id: notificationRef.id,
        ...notification,
      })
    );
  } catch (error) {
    console.error("Error uploading file:", error);
    res.status(500).send({ error: "Failed to upload file" });
  }
});

export const handler = serverless(app);
// app.listen(3000, () => {
//   console.log("Server running on port 3000");
// }); 
