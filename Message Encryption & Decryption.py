from tkinter import *
import base64

root=Tk()
root.geometry("1200x6000")
root.title("Message Encryption and Decryption")

Tops = Frame(root, width = 1600, relief = SUNKEN) 
Tops.pack(side = TOP) 
  
f1 = Frame(root, width = 800, height = 700, relief = SUNKEN) 
f1.pack(side = LEFT)

def qExit():
    root.destroy()

def Reset():
    Msg.set("") 
    key.set("") 
    mode.set("") 
    Result.set("")

def encode(key,msg):
    enc=[]
    for i in range(len(msg)):
        key_c = key[i % len(key)] 
        enc_c = chr((ord(msg[i]) + ord(key_c)) % 256)                
        enc.append(enc_c)   
    return base64.urlsafe_b64encode("".join(enc).encode()).decode() 
  
def decode(key,enc):
    dec = []   
    enc = base64.urlsafe_b64decode(enc).decode() 
    for i in range(len(enc)): 
        key_c = key[i % len(key)] 
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)                        
        dec.append(dec_c) 
    return "".join(dec) 

def Ref():
    msg=Msg.get()
    k=key.get()
    m=mode.get()
    if m=='e':
        Result.set(encode(k,msg))
    else:
        Result.set(decode(k,msg))
    

lbltop=Label(Tops,font=('Times New Roman',50,'bold'),text="SECRET MESSAGING",fg="Black",bd=10,anchor="center")
lbltop.grid(row=0,column=0)

lblmsg=Label(f1,font=('arial',16,'bold'),text="MESSAGE:",anchor="w")
lblmsg.grid(row=1,column=0)

Msg=StringVar()
txtmsg=Entry(f1,font=('arial',16,'bold'),textvariable=Msg,insertwidth=4,bg='powder blue',justify='right')
txtmsg.grid(row=1,column=1)

lblkey=Label(f1,font=('arial',16,'bold'),text="KEY:",anchor="w")
lblkey.grid(row=2,column=0)

key=StringVar()
txtkey=Entry(f1,font=('arial',16,'bold'),textvariable=key,insertwidth=4,bg='powder blue',justify='right')
txtkey.grid(row=2,column=1)

lblmode=Label(f1,font=('arial',16,'bold'),text="MODE(e for encrypt, d for decrypt):",anchor="w")
lblmode.grid(row=3,column=0)

mode=StringVar()
txtmode=Entry(f1,font=('arial',16,'bold'),textvariable=mode,insertwidth=4,bg="powder blue",justify='right')
txtmode.grid(row=3,column=1)

lblresult=Label(f1,font=('arial',16,'bold'),text="RESULT:",anchor="w")
lblresult.grid(row=2,column=2)

Result=StringVar()
txtresult=Entry(f1,font=('arial',16,'bold'),textvariable=Result,insertwidth=4,bg="powder blue",justify='right')
txtresult.grid(row=2,column=3)


show=Button(f1,padx=16,pady=8,fg="black",font=('arial',16,'bold'),width=10,text="Show Message",bg="powder blue",command=Ref)
show.grid(row=8,column=1)

reset=Button(f1,padx=16,pady=8,fg="black",font=('arial',16,'bold'),width=10,text="Reset",bg="green",command=Reset)
reset.grid(row=8,column=2)

btnexit=Button(f1,padx=16,pady=8,fg="black",font=('arial',16,'bold'),width=10,text="Exit",bg="red",command=qExit)
btnexit.grid(row=8,column=3)
               
root.mainloop()
