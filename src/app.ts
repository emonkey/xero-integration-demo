require("dotenv").config();
import * as bodyParser from "body-parser";
import * as crypto from 'crypto';
import express from "express";
import { Request, Response } from "express";
import { TokenSetParameters } from 'xero-node'
import * as fs from "fs";
import {
  Account,
  Accounts,
  AccountType,
  Contact,
  ContactPerson,
  Contacts,
  Invoice,
  Invoices,
  Item,
  Items,
  LineAmountTypes,
  Payment,
  Payments,
  XeroAccessToken,
  XeroClient,
  XeroIdToken
} from "xero-node";
import Helper from "./helper";
import jwtDecode from 'jwt-decode';

const session = require("express-session");
var FileStore = require('session-file-store')(session);
const path = require("path");
const mime = require("mime-types");

const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const redirectUrl = process.env.REDIRECT_URI;
const scopes = "offline_access openid profile email accounting.transactions accounting.settings.read accounting.contacts accounting.contacts.read";

const xero = new XeroClient({
  clientId: client_id,
  clientSecret: client_secret,
  redirectUris: [redirectUrl],
  scopes: scopes.split(" "),
  state: "imaParam=look-at-me-go",
  httpTimeout: 2000
});

if (!client_id || !client_secret || !redirectUrl) {
  throw Error('Environment Variables not all set - please check your .env file in the project root or create one!')
}

class App {
  public app: express.Application;
  public consentUrl: Promise<string>

  constructor() {
    this.app = express();
    this.config();
    this.routes();
    this.app.set("views", path.join(__dirname, "views"));
    this.app.set("view engine", "ejs");
    this.app.use(express.static(path.join(__dirname, "public")));

    this.consentUrl = xero.buildConsentUrl()
  }

  private config(): void {
    this.app.use(bodyParser.urlencoded({ extended: false }));
    this.app.use('/webhooks', bodyParser.raw({ type: 'application/json' }));
    this.app.use(bodyParser.json());
  }

  // helpers
  authenticationData(req, _res) {
    return {
      decodedIdToken: req.session.decodedIdToken,
      tokenSet: req.session.tokenSet,
      decodedAccessToken: req.session.decodedAccessToken,
      accessTokenExpires: this.timeSince(req.session.decodedAccessToken),
      allTenants: req.session.allTenants,
      activeTenant: req.session.activeTenant
    }
  }

  timeSince(token) {
    if (token) {
      const timestamp = token['exp']
      const myDate = new Date(timestamp * 1000)
      return myDate.toLocaleString()
    } else {
      return ''
    }
  }

  sleep(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };

  verifyWebhookEventSignature(req: Request) {
    let computedSignature = crypto.createHmac('sha256', process.env.WEBHOOK_KEY).update(req.body.toString()).digest('base64');
    let xeroSignature = req.headers['x-xero-signature'];

    if (xeroSignature === computedSignature) {
      console.log('Signature passed! This is from Xero!');
      return true;
    } else {
      // If this happens someone who is not Xero is sending you a webhook
      console.log('Signature failed. Webhook might not be from Xero or you have misconfigured something...');
      console.log(`Got {${computedSignature}} when we were expecting {${xeroSignature}}`);
      return false;
    }
  };

  private routes(): void {
    const router = express.Router();

    router.get("/", async (req: Request, res: Response) => {
      if (req.session.tokenSet) {
        // This reset the session and required data on the xero client after ts recompile
        await xero.setTokenSet(req.session.tokenSet)
        await xero.updateTenants(false)
      }

      try {
        const authData = this.authenticationData(req, res)

        res.render("home", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: authData
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/callback", async (req: Request, res: Response) => {
      try {
        // calling apiCallback will setup all the client with
        // and return the orgData of each authorized tenant
        const tokenSet: TokenSetParameters = await xero.apiCallback(req.url);
        await xero.updateTenants(false)

        console.log('xero.config.state: ', xero.config.state)

        // this is where you can associate & save your
        // `tokenSet` to a user in your Database
        req.session.tokenSet = tokenSet
        if (tokenSet.id_token) {
          const decodedIdToken: XeroIdToken = jwtDecode(tokenSet.id_token)
          req.session.decodedIdToken = decodedIdToken
        }
        const decodedAccessToken: XeroAccessToken = jwtDecode(tokenSet.access_token)
        req.session.decodedAccessToken = decodedAccessToken
        req.session.tokenSet = tokenSet
        req.session.allTenants = xero.tenants
        req.session.activeTenant = xero.tenants[0]

        res.render("callback", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res)
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.post("/change_organisation", async (req: Request, res: Response) => {
      try {
        const activeOrgId = req.body.active_org_id
        const picked = xero.tenants.filter((tenant) => tenant.tenantId == activeOrgId)[0]
        req.session.activeTenant = picked
        const authData = this.authenticationData(req, res)

        res.render("home", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res)
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/refresh-token", async (req: Request, res: Response) => {
      try {
        const tokenSet = await xero.readTokenSet();
        console.log('tokenSet.expires_in: ', tokenSet.expires_in, ' seconds')
        console.log('tokenSet.expires_at: ', tokenSet.expires_at, ' milliseconds')
        console.log('Readable expiration: ', new Date(tokenSet.expires_at * 1000).toLocaleString())
        console.log('tokenSet.expired(): ', tokenSet.expired());

        if (tokenSet.expired()) {
          console.log('tokenSet is currently expired: ', tokenSet)
        } else {
          console.log('tokenSet is not expired: ', tokenSet)
        }

        // you can refresh the token using the fully initialized client levereging openid-client
        await xero.refreshToken()

        // or if you already generated a tokenSet and have a valid (< 60 days refresh token),
        // you can initialize an empty client and refresh by passing the client, secret, and refresh_token
        const newXeroClient = new XeroClient()
        const newTokenSet = await newXeroClient.refreshWithRefreshToken(client_id, client_secret, tokenSet.refresh_token)
        const decodedIdToken: XeroIdToken = jwtDecode(newTokenSet.id_token);
        const decodedAccessToken: XeroAccessToken = jwtDecode(newTokenSet.access_token)

        req.session.decodedIdToken = decodedIdToken
        req.session.decodedAccessToken = decodedAccessToken
        req.session.tokenSet = newTokenSet
        req.session.allTenants = xero.tenants
        req.session.activeTenant = xero.tenants[0]

        const authData = this.authenticationData(req, res)

        res.render("home", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res)
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/disconnect", async (req: Request, res: Response) => {
      try {
        const updatedTokenSet: TokenSetParameters = await xero.disconnect(req.session.activeTenant.id)
        await xero.updateTenants(false)

        if (xero.tenants.length > 0) {
          const decodedIdToken: XeroIdToken = jwtDecode(updatedTokenSet.id_token);
          const decodedAccessToken: XeroAccessToken = jwtDecode(updatedTokenSet.access_token)
          req.session.decodedIdToken = decodedIdToken
          req.session.decodedAccessToken = decodedAccessToken
          req.session.tokenSet = updatedTokenSet
          req.session.allTenants = xero.tenants
          req.session.activeTenant = xero.tenants[0]
        } else {
          req.session.decodedIdToken = undefined
          req.session.decodedAccessToken = undefined
          req.session.allTenants = undefined
          req.session.activeTenant = undefined
        }
        const authData = this.authenticationData(req, res)

        res.render("home", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: authData
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/revoke-token", async (req: Request, res: Response) => {
      try {
        await xero.revokeToken();
        req.session.decodedIdToken = undefined
        req.session.decodedAccessToken = undefined
        req.session.tokenSet = undefined
        req.session.allTenants = undefined
        req.session.activeTenant = undefined

        res.render("home", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res)
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    })

    router.post("/webhooks", async (req: Request, res: Response) => {
      console.log("webhook event received!", req.headers, req.body, JSON.parse(req.body));
      this.verifyWebhookEventSignature(req) ? res.status(200).send() : res.status(401).send();
    });

    // ******************************************************************************************************************** ACCOUNTING API

    router.get("/accounts", async (req: Request, res: Response) => {
      try {
        // GET ALL
        const accountsGetResponse = await xero.accountingApi.getAccounts(req.session.activeTenant.tenantId);

        // // CREATE
        // // const account: Account = { name: "Foo" + Helper.getRandomNumber(1000000), code: "c:" + Helper.getRandomNumber(1000000), type: AccountType.EXPENSE, hasAttachments: true };
        // const account: Account = { name: "Foo", code: "c:", type: AccountType.EXPENSE, hasAttachments: true };
        // const accountCreateResponse = await xero.accountingApi.createAccount(req.session.activeTenant.tenantId, account);
        // const accountId = accountCreateResponse.body.accounts[0].accountID;

        // // GET ONE
        // const accountGetResponse = await xero.accountingApi.getAccount(req.session.activeTenant.tenantId, accountId);

        // // UPDATE
        // const accountUp: Account = { name: "Bar" + Helper.getRandomNumber(1000000) };
        // const accounts: Accounts = { accounts: [accountUp] };
        // const accountUpdateResponse = await xero.accountingApi.updateAccount(req.session.activeTenant.tenantId, accountId, accounts);

        // // CREATE ATTACHMENT
        // const filename = "xero-dev.png";
        // const pathToUpload = path.resolve(__dirname, "../public/images/xero-dev.png");
        // const readStream = fs.createReadStream(pathToUpload);
        // const contentType = mime.lookup(filename);

        // const accountAttachmentsResponse: any = await xero.accountingApi.createAccountAttachmentByFileName(req.session.activeTenant.tenantId, accountId, filename, readStream, {
        //   headers: {
        //     'Content-Type': contentType
        //   }
        // });

        // const attachment = accountAttachmentsResponse.body
        // const attachmentId = attachment.attachments[0].attachmentID

        // // GET ATTACHMENTS
        // const accountAttachmentsGetResponse = await xero.accountingApi.getAccountAttachments(req.session.activeTenant.tenantId, accountId);

        // // GET ATTACHMENT BY ID
        // const accountAttachmentsGetByIdResponse = await xero.accountingApi.getAccountAttachmentById(req.session.activeTenant.tenantId, accountId, attachmentId, contentType);
        // fs.writeFile(`img-temp-${filename}`, accountAttachmentsGetByIdResponse.body, (err) => {
        //   if (err) { throw err; }
        //   console.log("file written successfully");
        // });

        // // GET ATTACHMENT BY FILENAME
        // const accountAttachmentsGetByFilenameResponse = await xero.accountingApi.getAccountAttachmentByFileName(req.session.activeTenant.tenantId, accountId, filename, contentType);
        // fs.writeFile(`img-temp-${filename}`, accountAttachmentsGetByFilenameResponse.body, (err) => {
        //   if (err) { throw err; }
        //   console.log("file written successfully");
        // });

        // // DELETE
        // // let accountDeleteResponse = await xero.accountingApi.deleteAccount(req.session.activeTenant.tenantId, accountId);

        res.render("accounts", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res),
          accountsCount: accountsGetResponse.body.accounts.length,
          // getOneName: accountGetResponse.body.accounts[0].name,
          // createName: accountCreateResponse.body.accounts[0].name,
          // updateName: accountUpdateResponse.body.accounts[0].name,
          // attachments: accountAttachmentsGetResponse.body,
          // deleteName: 'un-comment to DELETE'
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/contacts", async (req: Request, res: Response) => {
      try {
        // GET ALL
        const contactsGetResponse = await xero.accountingApi.getContacts(req.session.activeTenant.tenantId);

        // CREATE ONE OR MORE
        const contact1: Contact = { name: "Rick James: " + Helper.getRandomNumber(1000000), firstName: "Rick", lastName: "James", emailAddress: "test@example.com" };
        const newContacts: Contacts = new Contacts();
        newContacts.contacts = [contact1];
        const contactCreateResponse = await xero.accountingApi.createContacts(req.session.activeTenant.tenantId, newContacts);
        const contactId = contactCreateResponse.body.contacts[0].contactID;

        // UPDATE or CREATE BATCH - force validation error
        const person: ContactPerson = {
          firstName: 'Joe',
          lastName: 'Schmo'
        }

        const updateContacts: Contacts = new Contacts();
        const contact2: Contact = {
          contactID: contactId,
          name: "Rick James: " + Helper.getRandomNumber(1000000),
          firstName: "Rick",
          lastName: "James",
          emailAddress: "test@example.com",
          contactPersons: [person]
        };
        const contact3: Contact = { name: "Rick James: " + Helper.getRandomNumber(1000000), firstName: "Rick", lastName: "James", emailAddress: "test@example.com" };

        updateContacts.contacts = [contact2, contact3];
        await xero.accountingApi.updateOrCreateContacts(req.session.activeTenant.tenantId, updateContacts, false);

        // GET ONE
        const contactGetResponse = await xero.accountingApi.getContact(req.session.activeTenant.tenantId, contactId);

        // UPDATE SINGLE
        const contactUpdate: Contact = { name: "Rick James Updated: " + Helper.getRandomNumber(1000000) };
        const contacts: Contacts = { contacts: [contactUpdate] };
        const contactUpdateResponse = await xero.accountingApi.updateContact(req.session.activeTenant.tenantId, contactId, contacts);

        // Technical Exercise: Upsert Rod Drury
        const contact4: ContactPerson = {

        }

        res.render("contacts", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res),
          contactsCount: contactsGetResponse.body.contacts.length,
          createName: contactCreateResponse.body.contacts[0].name,
          getOneName: contactGetResponse.body.contacts[0].name,
          updatedContact: contactUpdateResponse.body.contacts[0],
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/invoices", async (req: Request, res: Response) => {
      try {
        const brandingTheme = await xero.accountingApi.getBrandingThemes(req.session.activeTenant.tenantId);
        const num = Helper.getRandomNumber(1000000)
        const contact1: Contact = { name: "Test User: " + num, firstName: "Rick", lastName: "James", emailAddress: req.session.decodedIdToken.email };
        const newContacts: Contacts = new Contacts();
        newContacts.contacts = [contact1];
        await xero.accountingApi.createContacts(req.session.activeTenant.tenantId, newContacts);

        const contactsResponse = await xero.accountingApi.getContacts(req.session.activeTenant.tenantId);
        const selfContact = contactsResponse.body.contacts.filter(contact => contact.emailAddress === req.session.decodedIdToken.email);

        const where = 'Status=="' + Account.StatusEnum.ACTIVE + '" AND Type=="' + AccountType.EXPENSE + '"';
        const getAccountsResponse = await xero.accountingApi.getAccounts(req.session.activeTenant.tenantId, null, where);

        const invoice1: Invoice = {
          type: Invoice.TypeEnum.ACCREC,
          contact: {
            contactID: selfContact[0].contactID
          },
          expectedPaymentDate: "2009-10-20T00:00:00",
          invoiceNumber: `XERO:${Helper.getRandomNumber(1000000)}`,
          reference: `REF:${Helper.getRandomNumber(1000000)}`,
          brandingThemeID: brandingTheme.body.brandingThemes[0].brandingThemeID,
          url: "https://deeplink-to-your-site.com",
          hasAttachments: true,
          currencyCode: req.session.activeTenant.baseCurrency,
          status: Invoice.StatusEnum.SUBMITTED,
          lineAmountTypes: LineAmountTypes.Inclusive,
          subTotal: 87.11,
          totalTax: 10.89,
          total: 98.00,
          date: "2009-05-27T00:00:00",
          dueDate: "2009-06-06T00:00:00",
          lineItems: [
            {
              description: "Consulting services",
              taxType: "NONE",
              quantity: 20,
              unitAmount: 100.00,
              accountCode: getAccountsResponse.body.accounts[0].code
            },
            {
              description: "Mega Consulting services",
              taxType: "NONE",
              quantity: 10,
              unitAmount: 500.00,
              accountCode: getAccountsResponse.body.accounts[0].code
            }
          ]
        }

        // Array of Invoices needed
        const newInvoices: Invoices = new Invoices()
        newInvoices.invoices = [invoice1, invoice1];

        // CREATE ONE OR MORE INVOICES
        const createdInvoice = await xero.accountingApi.createInvoices(req.session.activeTenant.tenantId, newInvoices, false);
        // Since we are using summarizeErrors = false we get 200 OK statuscode
        // Our array of created invoices include those that succeeded and those with validation errors.
        // loop over the invoices and if it has an error, loop over the error messages
        for (let i = 0; i < createdInvoice.body.invoices.length; i++) {
          if (createdInvoice.body.invoices[i].hasErrors) {
            let errors = createdInvoice.body.invoices[i].validationErrors;
            for (let j = 0; j < errors.length; j++) {
              console.log(errors[j].message);
            }
          }
        }

        // CREATE ONE OR MORE INVOICES - FORCE Validation error with bad account code
        const updateInvoices: Invoices = new Invoices();
        const invoice2: Invoice = {
          type: Invoice.TypeEnum.ACCREC,
          contact: {
            contactID: selfContact[0].contactID
          },
          status: Invoice.StatusEnum.SUBMITTED,
          date: "2009-05-27T00:00:00",
          dueDate: "2009-06-06T00:00:00",
          lineItems: [
            {
              description: "Consulting services",
              taxType: "NONE",
              quantity: 20,
              unitAmount: 100.00,
              accountCode: "99999999"
            }
          ]
        }
        updateInvoices.invoices = [invoice1, invoice2];
        await xero.accountingApi.updateOrCreateInvoices(req.session.activeTenant.tenantId, updateInvoices, false)

        // GET ONE
        const getInvoice = await xero.accountingApi.getInvoice(req.session.activeTenant.tenantId, createdInvoice.body.invoices[0].invoiceID);
        const invoiceId = getInvoice.body.invoices[0].invoiceID

        // UPDATE
        const newReference = { reference: `NEW-REF:${Helper.getRandomNumber(1000000)}` }

        const invoiceToUpdate: Invoices = {
          invoices: [
            Object.assign(invoice1, newReference)
          ]
        }

        const updatedInvoices = await xero.accountingApi.updateInvoice(req.session.activeTenant.tenantId, invoiceId, invoiceToUpdate)

        // GET ALL
        const totalInvoices = await xero.accountingApi.getInvoices(req.session.activeTenant.tenantId);

        res.render("invoices", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res),
          invoiceId,
          email: req.session.decodedIdToken.email,
          createdInvoice: createdInvoice.body.invoices[0],
          updatedInvoice: updatedInvoices.body.invoices[0],
          count: totalInvoices.body.invoices.length
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/items", async (req: Request, res: Response) => {
      // currently works with DEMO COMPANY specific data.. Will need to create proper accounts
      // w/ cOGS codes to have this work with an empty Xero Org
      try {
        // GET ALL
        const itemsGetResponse = await xero.accountingApi.getItems(req.session.activeTenant.tenantId);

        // CREATE ONE or MORE ITEMS
        const item1: Item = {
          code: "Foo" + Helper.getRandomNumber(1000000),
          name: "Bar",
          purchaseDetails: {
            unitPrice: 375.5000,
            taxType: "NONE",
            accountCode: "500"
          },
          salesDetails: {
            unitPrice: 520.9900,
            taxType: "NONE",
            accountCode: "400",
          }
        };
        const newItems: Items = new Items();
        newItems.items = [item1]

        const itemCreateResponse = await xero.accountingApi.createItems(req.session.activeTenant.tenantId, newItems);
        const itemId = itemCreateResponse.body.items[0].itemID;

        // UPDATE OR CREATE ONE or MORE ITEMS - FORCE validation error on update
        item1.name = "Bar" + Helper.getRandomNumber(1000000)
        const updateItems: Items = new Items();
        updateItems.items = [item1]

        await xero.accountingApi.updateOrCreateItems(req.session.activeTenant.tenantId, updateItems, false);

        // GET ONE
        const itemGetResponse = await xero.accountingApi.getItem(req.session.activeTenant.tenantId, itemsGetResponse.body.items[0].itemID)

        // UPDATE
        const itemUpdate: Item = { code: "Foo" + Helper.getRandomNumber(1000000), name: "Bar - updated", inventoryAssetAccountCode: item1.inventoryAssetAccountCode };
        const items: Items = { items: [itemUpdate] };
        const itemUpdateResponse = await xero.accountingApi.updateItem(req.session.activeTenant.tenantId, itemId, items);

        // DELETE
        const itemDeleteResponse = await xero.accountingApi.deleteItem(req.session.activeTenant.tenantId, itemId);

        res.render("items", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res),
          itemsCount: itemsGetResponse.body.items.length,
          createName: itemCreateResponse.body.items[0].name,
          getOneName: itemGetResponse.body.items[0].name,
          updateName: itemUpdateResponse.body.items[0].name,
          deleteResponse: itemDeleteResponse.response.statusCode
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    router.get("/payments", async (req: Request, res: Response) => {
      try {
        //GET ALL
        const getPaymentsResponse = await xero.accountingApi.getPayments(req.session.activeTenant.tenantId);

        // CREATE
        // for that we'll need a contact & invoice
        const getContactsResponse = await xero.accountingApi.getContacts(req.session.activeTenant.tenantId);
        const invoices: Invoices = {
          invoices: [
            {
              type: Invoice.TypeEnum.ACCREC,
              contact: {
                contactID: getContactsResponse.body.contacts[0].contactID
              },
              lineItems: [
                {
                  description: "Acme Tires",
                  quantity: 2.0,
                  unitAmount: 20.0,
                  accountCode: "200",
                  taxType: "OUTPUT",
                  lineAmount: 40.0
                }
              ],
              date: "2019-03-11",
              dueDate: "2018-12-10",
              reference: "Website Design",
              status: Invoice.StatusEnum.AUTHORISED
            }
          ]
        };

        const createInvoiceResponse = await xero.accountingApi.createInvoices(req.session.activeTenant.tenantId, invoices);

        const payments: Payments = {
          payments: [
            {
              invoice: {
                invoiceID: createInvoiceResponse.body.invoices[0].invoiceID
              },
              account: {
                code: "090"
              },
              date: "2020-03-12",
              amount: 3.50
            },
          ]
        };

        const createPaymentResponse = await xero.accountingApi.createPayments(req.session.activeTenant.tenantId, payments);

        // GET ONE
        const getPaymentResponse = await xero.accountingApi.getPayment(req.session.activeTenant.tenantId, createPaymentResponse.body.payments[0].paymentID);

        // DELETE
        // spec needs to be updated, it's trying to modify a payment but that throws a validation error

        res.render("payments", {
          consentUrl: await xero.buildConsentUrl(),
          authenticated: this.authenticationData(req, res),
          count: getPaymentsResponse.body.payments.length,
          newPayment: createPaymentResponse.body.payments[0].paymentID,
          getPayment: getPaymentResponse.body.payments[0].invoice.contact.name
        });
      } catch (e) {
        res.status(res.statusCode);
        res.render("shared/error", {
          consentUrl: await xero.buildConsentUrl(),
          error: e
        });
      }
    });

    const fileStoreOptions = {}

    this.app.use(session({
      secret: "something crazy",
      store: new FileStore(fileStoreOptions),
      resave: false,
      saveUninitialized: false,
      cookie: { secure: false },
    }));

    this.app.use("/", router);
  }
}

export default new App().app;
