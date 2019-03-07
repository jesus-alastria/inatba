# -*- coding: utf-8 -*-
import os
#from gluon.debug import dbg
#    dbg.set_trace()


# Main page
def indexold():
    s = db(db.signature.signer_id == db.auth_user.id).select(db.signature.imagesvg, db.auth_user.organization, db.auth_user.first_name, db.auth_user.last_name)

    return dict(records=s)

# Main page
def index():
    s = db(db.signature.signer_id == db.auth_user.id).select(db.signature.imagesvg, db.auth_user.organization, db.auth_user.first_name, db.auth_user.last_name)

    return dict(records=s)

def test():
    result = mail.send('hesus.ruiz@gmail.com', 'Message subject', 'Plain text body of the message')
    return result


def getversion():
    import sys
    return sys.version_info[0]

# Convert document to a PDF file and register in Alastria
@auth.requires_membership('registrar')
def registerinblockchain():

    # Get all the records from the database
    s = db(db.signature.signer_id == db.auth_user.id).select(db.signature.id, db.signature.imagesvg, db.auth_user.organization, db.auth_user.first_name, db.auth_user.last_name)

    from weasyprint import HTML

    # Get the html template to render for this controller/action
    filename = '%s/%s.html' % (request.controller,request.function)

    # Render the template to html with the current variables
    the_html=response.render(filename, dict(records=s))

    # Create the file name with the time stamp on it
    import time
    timestr = time.strftime("%Y%m%d-%H%M%S")
    htmlName = "inatba-" + timestr + ".html"

    # Write the pdf to a file
    pdfPath = os.path.join(request.folder,'static', 'files', htmlName)
#        HTML(string=the_html).write_pdf(pdfPath)
    with open(pdfPath, "wb") as f:
        f.write(the_html.encode())

#        dbg.set_trace()

    # Read the file again as binary
    with open(pdfPath, "rb") as f:
        the_pdf = f.read()


    # Calculate the hash of the file
    import hashlib
    the_hash = hashlib.sha256(the_pdf).hexdigest()

    # Register the hash in Alastria
    result, txhash, receipt = __notarizeInAlastria(the_hash)

    # Insert a record with the blockchain transaction in the database
    uniqueID = db.regalastria.insert(
        blocknumber=receipt.blockNumber, 
        blockhash=receipt.blockHash.hex(),
        dochash=the_hash,
        txhash=txhash, 
        charter=the_pdf)


    # Set the response type
    response.headers['Content-Type'] = 'text/html'

    response.view = "default/resultofregistration.html"

    # Redirect to the result page
    return dict(result=result, txhash=txhash, receipt=receipt, pdfName=htmlName)


# Convert document to a PDF file and register in Alastria
@auth.requires_membership('registrar')
def registerinblockchainold():

    # Get all the records from the database
    s = db(db.signature.signer_id == db.auth_user.id).select(db.signature.id, db.signature.imagesvg, db.auth_user.organization, db.auth_user.first_name, db.auth_user.last_name)

    from weasyprint import HTML

    # Get the html template to render for this controller/action
    filename = '%s/%s.html' % (request.controller,request.function)

    # Render the template to html with the current variables
    the_html=response.render(filename, dict(records=s))

    # Create the file name with the time stamp on it
    import time
    timestr = time.strftime("%Y%m%d-%H%M%S")
    htmlName = "inatba-" + timestr + ".html"

    # Write the pdf to a file
    pdfPath = os.path.join(request.folder,'static', 'files', htmlName)
#        HTML(string=the_html).write_pdf(pdfPath)
    with open(pdfPath, "wb") as f:
        f.write(the_html.encode())

#        dbg.set_trace()

    # Read the file again as binary
    with open(pdfPath, "rb") as f:
        the_pdf = f.read()


    # Calculate the hash of the file
    import hashlib
    the_hash = hashlib.sha256(the_pdf).hexdigest()

    # Register the hash in Alastria
    result, txhash, receipt = __notarizeInAlastria(the_hash)

    # Insert a record with the blockchain transaction in the database
    uniqueID = db.regalastria.insert(
        blocknumber=receipt.blockNumber, 
        blockhash=receipt.blockHash.hex(),
        dochash=the_hash,
        txhash=txhash, 
        charter=the_pdf)


    # Set the response type
    response.headers['Content-Type'] = 'text/html'

    response.view = "default/resultofregistration.html"

    # Redirect to the result page
    return dict(result=result, txhash=txhash, receipt=receipt, pdfName=htmlName)




# Notarize the document hash in Alastria and return the transaction hash
def __notarizeInAlastria(documentHash="", notaryID="Alastria", docURI="", payload=""):

    import json
    import web3

    from web3 import Web3
    from web3.contract import ConciseContract

    providerComillas = "http://130.206.64.6:22000"
    providerBabel = "http://213.27.216.170:22000"


    # Create a web3 instance with the right provider
    w3 = setup_provider(providerBabel)

    # Read the last compiled contract
    lastCompilation = os.path.join(request.folder,'static', 'alastria', 'lastCompilation.txt')
    with open(lastCompilation) as f:
        compiled_sol = json.loads(f.read())


    # Read the last deployment address
    raw_contract_address = "0x41b4379b0AB1d760BFe54E0d75dF25C19855c78B"

    # Get the contract wrapper to be able to call its functions
    proofOfEx = bind_compiled_contract(w3, compiled_sol, raw_contract_address)

    # Invoke the method as a signed transaction with the first private key
    # and wait 16 seconds for the transaction to be mined in the blockchain

    result, receipt, tx_hash = send_signed_tx(
        w3,
        proofOfEx.functions.notarize(documentHash, notaryID, docURI, payload),
        privKey1,
        16)

    # Check if transaction was executed correctly
    if result == False:
        return result, tx_hash, receipt

    # The transaction executed correctly. Return the txhash and the receipt
    return result, tx_hash.hex(), receipt




# Add signature page
@auth.requires_login()
def addSignature():
    return dict(pepe="pepe")

# Store signature in database and display result
@auth.requires_login()
def storeAndDisplayResult():
    import base64

    #dbg.set_trace()

    # Retrieve the signature bytes from the request
    imageSVG = request.post_vars.the_image

    # Calculate the hash of the signature bytes
    import hashlib
    the_hash = hashlib.sha256(imageSVG.encode()).hexdigest()

    # Register the hash in Alastria
    result, txhash, receipt = __notarizeInAlastria(documentHash=the_hash, notaryID=db.auth_user[auth.user_id].organization)


    # Insert a record with the signature in the database
    uniqueID = db.signature.insert(signer_id=auth.user_id, txhash=txhash, imagesvg=imageSVG)

    #Decode Image and store on disk
#    prefixLength = len("data:image/png;base64,")
#    imgBase64 = imageSVG[prefixLength:]
    # imgDecoded = base64.b64decode(imgBase64)


    # imagesPath = os.path.join(request.folder,'static', 'signatures')
    # fileName = "sigimage." + str(uniqueID) + ".png"
    # fullFileName = os.path.join(imagesPath, fileName)
    # with open(fullFileName, "wb") as f:
    #     f.write(imgDecoded)

    return dict(result=result, txhash=txhash, receipt=receipt)


# ---- Smart Grid (example) -----
@auth.requires_membership('admin')
def grid():
    response.view = 'generic.html' # use a generic view
    tablename = request.args(0)
    if not tablename in db.tables: raise HTTP(403)
    grid = SQLFORM.smartgrid(db[tablename], args=[tablename], deletable=True, editable=True)
    return dict(grid=grid)


# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """
    return dict(form=auth())

# Convert document to a PDF file and register in Alastria
@auth.requires_membership('registrar')
def topdf_old_was_working():

    # Get all the records from the database
    s = db().select(db.signature.id, db.signature.imagesvg, db.auth_user.organization, db.auth_user.first_name, db.auth_user.last_name)

    # Check if the user requested the extension ".pdf"
    if request.extension == "pdf":

        from weasyprint import HTML

        # Get the html template to render for this controller/action
        filename = '%s/%s.html' % (request.controller,request.function)

        # Render the template to html with the current variables
        the_html=response.render(filename, dict(records=s))

        # Create the file name with the time stamp on it
        import time
        timestr = time.strftime("%Y%m%d-%H%M%S")
        pdfName = "inatba-" + timestr + ".pdf"

        # Write the pdf to a file
        pdfPath = os.path.join(request.folder,'static', 'files', pdfName)
        HTML(string=the_html).write_pdf(pdfPath)

#        dbg.set_trace()

        # Read the file again as binary
        with open(pdfPath, "rb") as f:
            the_pdf = f.read()

        # Calculate the hash of the file
        import hashlib
        the_hash = hashlib.sha256(the_pdf).hexdigest()

        # Register the hash in Alastria
        result, txhash, receipt = __notarizeInAlastria(documentHash=the_hash)

        # Set the response type
        response.headers['Content-Type'] = 'text/html'

        response.view = "default/resultofregistration.html"

        # Redirect to the result page
        return dict(result=result, txhash=txhash, receipt=receipt, pdfName=pdfName)
    else:
        return dict(records=s)

