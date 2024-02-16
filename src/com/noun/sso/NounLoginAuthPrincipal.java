package com.noun.sso;

import java.io.Serializable;

import javax.security.auth.Subject;

public class NounLoginAuthPrincipal implements java.security.Principal, Serializable {

	private final String name;
	private final String colon = " : ";
	
	public NounLoginAuthPrincipal(String name)
	{
		if(name==null)
		{
			throw new NullPointerException("Username must be provided");
		}
		this.name = name;
	}
	
    public String toString()
    {
        return new StringBuilder().append(NounLoginAuthPrincipal.class.getCanonicalName()).append(colon)
                .append(this.name).toString();
    }
	
	public boolean equals(Object o)
    {
        if (o == null)
        {
            return false;
        }

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof NounLoginAuthPrincipal))
        {
            return false;
        }
        NounLoginAuthPrincipal that = (NounLoginAuthPrincipal) o;

        if (this.getName().equals(that.getName()))
        {
            return true;
        }
        return false;
    }
	
	public String getName() {
		// TODO Auto-generated method stub
		return this.name;
	}

	public boolean implies(Subject arg0) {
		// TODO Auto-generated method stub
		if(arg0!=null && arg0.getPrincipals().contains(this))
			return true;
		else 
			return false;
	}
	
	public int hashCode()
	{
	    return name.hashCode();
	}

}
