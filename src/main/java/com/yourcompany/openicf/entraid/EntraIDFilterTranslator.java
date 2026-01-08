package com.yourcompany.openicf.entraid;

import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

/**
 * Translates OpenICF filters into Microsoft Graph OData query strings.
 * <p>
 * This class handles the mapping of standard OpenICF filter operations (like
 * Equals
 * and Contains) to their OData equivalents (eq and startsWith).
 * </p>
 */
public class EntraIDFilterTranslator extends AbstractFilterTranslator<String> {

    /**
     * Translates an usage of {@link EqualsFilter}.
     * Maps to OData 'eq' operator.
     * 
     * @param filter The Equals filter.
     * @param not    True if this is a NOT expression (not supported).
     * @return The OData query string (e.g., "displayName eq 'bob'").
     */
    @Override
    protected String createEqualsExpression(EqualsFilter filter, boolean not) {
        if (not) {
            return null; // Not supported
        }
        Attribute attr = filter.getAttribute();
        String name = attr.getName();
        String value = AttributeUtil.getStringValue(attr);

        if (value == null) {
            return null;
        }

        return String.format("%s eq '%s'", name, value);
    }

    /**
     * Translates an usage of {@link ContainsFilter}.
     * Maps to OData 'startsWith' function.
     * 
     * @param filter The Contains filter.
     * @param not    True if this is a NOT expression (not supported).
     * @return The OData query string (e.g., "startsWith(displayName, 'bob')").
     */
    @Override
    protected String createContainsExpression(ContainsFilter filter, boolean not) {
        if (not) {
            return null; // Not supported
        }
        Attribute attr = filter.getAttribute();
        String name = attr.getName();
        String value = AttributeUtil.getStringValue(attr);

        if (value == null) {
            return null;
        }

        return String.format("startsWith(%s, '%s')", name, value);
    }

    /**
     * Combines two expressions with AND.
     * 
     * @param leftExpression  The left expression.
     * @param rightExpression The right expression.
     * @return The combined OData query string.
     */
    @Override
    protected String createAndExpression(String leftExpression, String rightExpression) {
        return String.format("(%s and %s)", leftExpression, rightExpression);
    }

    /**
     * Combines two expressions with OR.
     * 
     * @param leftExpression  The left expression.
     * @param rightExpression The right expression.
     * @return The combined OData query string.
     */
    @Override
    protected String createOrExpression(String leftExpression, String rightExpression) {
        return String.format("(%s or %s)", leftExpression, rightExpression);
    }
}
